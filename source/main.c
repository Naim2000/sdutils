#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gccore.h>
#include <ogc/machine/processor.h>

#include "video.h"
#include "pad.h"
#include "sd.h"

#define isPowerOfTwo(x) (x && (x & (x - 1)) == 0)

union chs {
	u8 chs8[3];
	u32 chs24: 24;
	struct {
		u8 head;
		u8 cylinder_h: 2;
		u8 sector: 6;
		u8 cylinder_l;
	};
} __attribute__((packed));

typedef struct MBRPartition {
	union {
		u8 status;
		struct {
			u8 active: 1;
			u8 :0;
		};
	};
	union chs chs_start;
	u8  type;
	union chs chs_end;
	u32 lba_start;
	u32 lba_count;
} __attribute__((packed)) MBRPartition;
_Static_assert(sizeof(MBRPartition) == 0x10, "MBRPartition size incorrect");

enum BPB {
	BPB_jmpBoot = 0x00,
	BPB_OEMName = 0x03,
	// BIOS Parameter Block
	BPB_bytesPerSector = 0x0B,
	BPB_sectorsPerCluster = 0x0D,
	BPB_reservedSectors = 0x0E,
	BPB_numFATs = 0x10,
	BPB_rootEntries = 0x11,
	BPB_numSectorsSmall = 0x13,
	BPB_mediaDesc = 0x15,
	BPB_sectorsPerFAT = 0x16,
	BPB_sectorsPerTrk = 0x18,
	BPB_numHeads = 0x1A,
	BPB_numHiddenSectors = 0x1C,
	BPB_numSectors = 0x20,
	// Ext BIOS Parameter Block for FAT16
	BPB_FAT16_driveNumber = 0x24,
	BPB_FAT16_reserved1 = 0x25,
	BPB_FAT16_extBootSig = 0x26,
	BPB_FAT16_volumeID = 0x27,
	BPB_FAT16_volumeLabel = 0x2B,
	BPB_FAT16_fileSysType = 0x36,
	// Bootcode
	BPB_FAT16_bootCode = 0x3E,
	// FAT32 extended block
	BPB_FAT32_sectorsPerFAT32 = 0x24,
	BPB_FAT32_extFlags = 0x28,
	BPB_FAT32_fsVer = 0x2A,
	BPB_FAT32_rootClus = 0x2C,
	BPB_FAT32_fsInfo = 0x30,
	BPB_FAT32_bkBootSec = 0x32,
	// Ext BIOS Parameter Block for FAT32
	BPB_FAT32_driveNumber = 0x40,
	BPB_FAT32_reserved1 = 0x41,
	BPB_FAT32_extBootSig = 0x42,
	BPB_FAT32_volumeID = 0x43,
	BPB_FAT32_volumeLabel = 0x47,
	BPB_FAT32_fileSysType = 0x52,
	// Bootcode
	BPB_FAT32_bootCode = 0x5A,
	BPB_bootSig_55 = 0x1FE,
	BPB_bootSig_AA = 0x1FF
};

enum {
	Invalid = -1,
	Unknown = 0,
	MBR = 1,
	FAT = 2,
	FAT32 = 3,
};

static int examine_bootsector(void* ptr) {
	u8* bootsect = ptr;

	const bool has_sig_55AA   = bootsect[BPB_bootSig_55] == 0x55 && bootsect[BPB_bootSig_AA] == 0xAA;
	const bool has_jmp_instr  = bootsect[BPB_jmpBoot] == 0xEB || bootsect[BPB_jmpBoot] == 0xE9 || bootsect[BPB_jmpBoot] == 0xE8;
	MBRPartition* partitions = (MBRPartition*) (bootsect + 0x1BE);

	if (has_sig_55AA && has_jmp_instr && !memcmp(bootsect + BPB_FAT32_fileSysType, "FAT32   ", 8)) {
		return FAT32;
	}
	// FATFS style
	else if (has_jmp_instr &&
			 isPowerOfTwo(__lhbrx(bootsect, BPB_bytesPerSector)) &&
			 isPowerOfTwo(bootsect[BPB_sectorsPerCluster]) &&
			 __lhbrx(bootsect, BPB_reservedSectors) != 0 &&
			 (bootsect[BPB_numFATs] - 1) <= 1 &&
			 __lhbrx(bootsect, BPB_rootEntries) != 0 &&
			 (__lhbrx(bootsect, BPB_numSectorsSmall) >= 128 || __lwbrx(bootsect, BPB_numSectors) >= 0x10000) &&
			 __lhbrx(bootsect, BPB_sectorsPerFAT) != 0) {
		return FAT;
	}
	else if (has_sig_55AA && partitions[0].type && partitions[0].lba_start) {
		return MBR;
	}
	else {
		return has_sig_55AA ? Unknown : Invalid;
	}
}

#define SelectionMenu(...) _SelectionMenu((const char* const[]){ __VA_ARGS__, NULL } )
static int _SelectionMenu(const char* const options[]) {
	int posX, posY, selected = 0;
	CON_GetPosition(&posX, &posY);

	int count = -1;
	while (options[++count]);

	while (true) {
		printf("\x1b[%i;0H", posY);
		for (int i = 0; i < count; i++)
			printf("	%s %s%s\n", i == selected ? "\x1b[47;1m\x1b[30m>>" : "  ", options[i], i == selected ? "\x1b[40m\x1b[39m" : "");

		wait_button(0);

		if (buttons_down(WPAD_BUTTON_UP)) {
			if (!selected--)
				selected = count - 1;
			continue;
		}

		else if (buttons_down(WPAD_BUTTON_DOWN)) {
			if (++selected == count)
				selected = 0;
			continue;
		}

		else if (buttons_down(WPAD_BUTTON_A)) {
			selected++;
			break;
		}

		else if (buttons_down(WPAD_BUTTON_HOME)) {
			selected = -1;
			break;
		}
	}

	putchar('\n');
	putchar('\n');
	return selected;
}

void show_sd_cardinfo(void) {
	struct cid cid;
	struct csd csd;

	sd_decode_cid(0, &cid);
	sd_decode_csd(0, &csd);

	printf("SD Manufacturer ID:  0x%02x\n", cid.manfid);
	printf("SD OEM ID:           %.2s (0x%04x)\n", (const char*) &cid.oemid, cid.oemid);
	printf("SD Product name:     %.5s\n", cid.name);
	printf("SD Revision:         %u.%u (0x%02x)\n", cid.hwrev, cid.fwrev, cid.prv);
	printf("SD Serial number:    0x%08x\n", cid.serial);
	printf("SD Manufacture date: %02u/%04u\n", cid.mdt_mon, cid.mdt_year);

	printf("SD Command Classes:  %03x\n", csd.cmdclass);

	for (int i = 0; i < 12; i++) {
		static const char* cmdclass_names[12] =
			{
				"Basic",
				"Command queue",
				"Block read",
				"<reserved>",
				"Block write",
				"Erase",
				"Write protection",
				"Password lock",
				"Application-specific commands",
				"I/O mode",
				"Switch",
				"Extension"
			};

		if (csd.cmdclass & (1 << i))
			printf("+ (%u) %s\n", i, cmdclass_names[i]);
	}
	printf("SD Capacity:         %llu MiB (%#llx)\n", csd.capacity >> (20 - 9), csd.capacity);

	static const char* wrprot_type[4] = { "None", "Temporary", "\x1b[41mPermanent\x1b[40m", "\x1b[41mPermanent(+)\x1b[40m" };
	printf("SD Write protection: %s\n", wrprot_type[csd.write_protect]);
}

void show_sd_bsinfo(void) {
	static u32 sector0[0x80];
	u8* bootsect = (u8*) sector0;

	int ret = sd_read(0, 1, sector0);
	if (ret < 0) {
		printf("sd_read failed (%i)\n", ret);
		return;
	}
	int type = examine_bootsector(sector0);

	while (true) {
		clear();
		switch (type) {
			case MBR: {
				MBRPartition* partitions = (MBRPartition*) (bootsect + 0x1BE);

				printf("Boot sector type: MBR\n");
				for (int i = 0; i < 4; i++) {
					MBRPartition* part = &partitions[i];
					if (partitions[i].type) {
						printf("Partition %i:\n", i + 1);

						printf("+ Type:        %#x\n", part->type);
						printf("+ Active:      %s\n", part->active ? "Yes" : "No");
						if (part->chs_start.chs24 != 0xFFFFFF && part->chs_start.sector) {
							printf("+ Start (CHS): %u-%u-%u\n", part->chs_start.cylinder_h << 8 | part->chs_start.cylinder_l, part->chs_start.head, part->chs_start.sector);
							printf("+ End (CHS):   %u-%u-%u\n", part->chs_end.cylinder_h << 8 | part->chs_end.cylinder_l, part->chs_end.head, part->chs_end.sector);
						}
						printf("+ Start (LBA): %#x (%u)\n", bswap32(part->lba_start), bswap32(part->lba_start));
						printf("+ Size (LBA):  %#x (%u)\n", bswap32(part->lba_count), bswap32(part->lba_count));
					}
				}
			} break;

			case FAT:
			case FAT32: {
				printf("Boot sector type:    FAT\n");
				u16 logicalSectorSize = __lhbrx(bootsect, BPB_bytesPerSector);
				u8  sectorsPerCluster = bootsect[BPB_sectorsPerCluster];
				u16 clusterSize       = logicalSectorSize * sectorsPerCluster;
				u16 reservedSectors   = __lhbrx(bootsect, BPB_reservedSectors);
				u8  numFATs           = bootsect[BPB_numFATs];
				u8  mediaType         = bootsect[BPB_mediaDesc];

				printf("OEM name:            %s\n", bootsect + BPB_OEMName);
				printf("Logical sector size: %u\n", logicalSectorSize);
				printf("Sectors per cluster: %u\n", sectorsPerCluster);
				printf("Cluster size:        %u\n", clusterSize);
				printf("Reserved sectors:    %u\n", reservedSectors);
				printf("# of FATs:           %u\n", numFATs);
				printf("Media descriptor:    %#x\n", mediaType);
			}
			break;

			default:
				printf("Boot sector type: unknown (%i)\n", type);
				break;
		}

		printf("\n");
		switch (SelectionMenu("Show raw sector 0", "Back")) {
			case 1: {
				clear();
				printf("Sector 0 data:\n");
				for (int i = 0; i < 0x80; i += 8)
					printf("%08x %08x %08x %08x %08x %08x %08x %08x\n",
						   sector0[i+0], sector0[i+1], sector0[i+2], sector0[i+3], sector0[i+4], sector0[i+5], sector0[i+6], sector0[i+7]);

				puts("\nPress any button to continue...");
				wait_button(0);
			} break;

			default: {
				return;
			} break;
		}
	}
}

int main(int argc, char **argv) {
	puts("Hello World!");

	initpads();
	int ret = sd_init();
	if (ret < 0) {
		printf("sd_init() failed (%i)\n", ret);
		goto waitexit;
	}

	while (true) {
		clear();
		printf("SD utils by thepikachugamer\n\n");

		switch (SelectionMenu("Show CID/CSD info", "Show boot sector info", "Press HOME to exit")) {
			case 1: {
				show_sd_cardinfo();
				puts("\nPress any button to continue...");
				wait_button(0);
			} break;

			case 2: {
				show_sd_bsinfo();
			} break;

			default: {
				goto exit;
			} break;
		}
	}

waitexit:
	puts("Press any button to exit.");
	wait_button(0);
exit:
	sd_close();
	return 0;
}
