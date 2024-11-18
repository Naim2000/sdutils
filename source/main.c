#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <gccore.h>
#include <fat.h>
#include <ogc/sha.h>
#include <ogc/aes.h>

#include "video.h"
#include "pad.h"
#include "sd.h"
#include "sd_dvm.h"

#define bswap16 __builtin_bswap16
#define bswap32 __builtin_bswap32
#define isPowerOfTwo(x) (x && (x & (x - 1)) == 0)

typedef union __attribute__((packed)) CHS {
	u8 chs8[3];
	u32 chs24: 24;
	struct {
		u8 head;
		u8 cylinder_h: 2;
		u8 sector: 6;
		u8 cylinder_l;
	};
} CHS;

typedef enum MBRPartitionType: u8 {
	None   = 0x00,
	FAT12C = 0x01,
	FAT16B = 0x04,
	FAT16C = 0x06,
	exFAT  = 0x07,
	NTFS   = 0x07,
	FAT32C = 0x0b,
	FAT32L = 0x0c,
	FAT16L = 0x0e,
	Linux  = 0x83,
	GPT    = 0xee,
} MBRPartitionType;

typedef struct __attribute__((packed)) MBRPartition {
	u8                status;
	CHS               chs_start;
	MBRPartitionType  type;
	CHS               chs_end;
	u32               lba_start;
	u32               lba_count;
} MBRPartition;
_Static_assert(sizeof(MBRPartition) == 0x10, "MBRPartition size incorrect");

// Thank you sdFormatLinux
typedef struct __attribute__((packed)) bootsect {
	union __attribute__((packed)) {
		struct __attribute__((packed)) mbr {
			u8           code[0x1BE];
			MBRPartition partitions[4];
		} mbr;
		struct __attribute__((packed)) fat_vbr {
			u8   jmpBoot[3];
			char oemName[8];
			u16  bytesPerSector;
			u8   sectorsPerCluster;
			u16  reservedSectors;
			u8   numFATs;
			u16  rootEntries;
			u16  totalSectors16;
			u8   mediaType;
			u16  sectorsPerFAT;
			u16  sectorsPerTrack;
			u16  numHeads;
			u32  numHiddenSectors;
			u32  totalSectors32;
			union __attribute__((packed)) {
				struct __attribute__((packed)) vi {
					u8   driveNumber;
					u8   reserved;
					u8   extBootSig; // 0x29
					u32  volumeID;
					char volumeLabel[11];
					char fsType[8];
					u8   code[];
				} ebpb;
				struct __attribute__((packed)) {
					u32  sectorsPerFAT;
					u16  extFlags;
					u16  fsVer;
					u32  rootDirCluster;
					u16  fsInfoSector;
					u16  bkBootSector;
					u8   reserved[12];
					struct vi vi;
				} ebpb32[1];
			};
		} fat_vbr;
	};
	u16 sig;
} bootsect;
_Static_assert(sizeof(bootsect) == 0x200, "Boot sector is not a sector");

#define FSI_SIGNATURE1 0x52526141
#define FSI_SIGNATURE2 0x72724161
#define FSI_SIGNATURE3 0x000055AA
// FAT32
typedef struct __attribute__((packed)) FSInfoSector {
	u32 signature1;
	u8  unused1[0x1E0];
	u32 signature2;
	u32 freeClusters;
	u32 lastAllocatedCluster;
	u8  unused2[0xC];
	u32 signature3;
} FSInfoSector;
_Static_assert(sizeof(FSInfoSector) == 0x200, "FS Info sector is not a sector");

enum {
	Invalid = -1,
	Unknown = 0,
	MBR = 1,
	FAT = 2,
	FAT32 = 3,
};

static int examine_bootsector(void* ptr) {
	bootsect* bootsect = ptr;

	const bool has_sig_55AA   = bootsect->sig == 0x55AA;
	const bool has_jmp_instr  = bootsect->fat_vbr.jmpBoot[0] == 0xEB || bootsect->fat_vbr.jmpBoot[0] == 0xE9 || bootsect->fat_vbr.jmpBoot[0] == 0xE8;

	// FATFS style
	if (has_jmp_instr) {
		struct fat_vbr* vbr = &bootsect->fat_vbr;
		if (has_sig_55AA && !memcmp(vbr->ebpb32->vi.fsType, "FAT32   ", 8)) {
			return FAT32;
		}
		else if (has_jmp_instr &&
			isPowerOfTwo(bswap16(vbr->bytesPerSector)) &&
			isPowerOfTwo(vbr->sectorsPerCluster) &&
			vbr->reservedSectors != 0 &&
			(vbr->numFATs - 1) <= 1 &&
			bswap16(vbr->rootEntries) != 0 &&
			(bswap16(vbr->totalSectors16) >= 128 || bswap32(vbr->totalSectors32) >= 0x10000) &&
			bswap16(vbr->sectorsPerFAT) != 0) {

			return FAT;
		}
	}

	else if (has_sig_55AA && bootsect->mbr.partitions[0].type && bootsect->mbr.partitions[0].lba_start) {
		return MBR;
	}
	else {
		return has_sig_55AA ? Unknown : Invalid;
	}

	return Invalid;
}

#define SelectionMenu(...) _SelectionMenu((const char* const[]){ __VA_ARGS__, NULL } )
static int _SelectionMenu(const char* const options[]) {
	int posX, posY, conX, conY;
	int selected = 0;
	CON_GetMetrics(&conX, &conY);
	CON_GetPosition(&posX, &posY);

	int count = -1;
	while (options[++count]);

	if (posY + count > conY) posY = (conY - 1) - count;

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
			selected = 0;
			break;
		}
	}

	putchar('\n');
	return selected;
}

void show_sd_cardinfo(void) {
	struct cid cid;
	struct csd csd;
	u32 cid_raw[4];

	if (!(sd_status() & SD_INITIALIZED)) {
		printf("SD card not initialized?");
		return;
	}

	sd_decode_cid(cid_raw, &cid);
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
	printf("SD Capacity:         %u MiB (%#x)\n", csd.capacity >> (20 - 9), csd.capacity);

	static const char* wrprot_type[4] = { "None", "Temporary", "\x1b[41mPermanent\x1b[40m", "\x1b[41mPermanent(+)\x1b[40m" };
	printf("SD Write protection: %s\n\n", wrprot_type[csd.write_protect]);

	printf("Nintendo 3DS ID1:    %08x%08x%08x%08x\n", cid_raw[0], cid_raw[1], cid_raw[2], cid_raw[3]);
}

static void print_bsinfo(u32* sector) {
	int type = examine_bootsector(sector);
	switch (type) {
		case MBR: {
			struct mbr* mbr = (struct mbr*)sector;

			printf("Boot sector type: MBR\n");
			for (int i = 0; i < 4; i++) {
				MBRPartition* part = &mbr->partitions[i];
				if (part->type) {
					printf("Partition %i:\n", i + 1);

					printf("+ Type:        %#x\n", part->type);
					printf("+ Active:      %s\n", part->status & 0x80 ? "Yes" : "No");
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
			struct fat_vbr* vbr = (struct fat_vbr*)sector;
			struct vi* vi       = (type == FAT32) ? &vbr->ebpb32->vi : &vbr->ebpb;

			printf("Boot sector type:    VFAT\n");

			u16 logicalSectorSize = bswap16(vbr->bytesPerSector);
			u8  sectorsPerCluster = vbr->sectorsPerCluster;
			u16 clusterSize       = logicalSectorSize * sectorsPerCluster;

			printf("OEM name:            %s\n", vbr->oemName);
			printf("Cluster size:        %u\n", clusterSize);
			printf("Reserved sectors:    %u\n", bswap16(vbr->reservedSectors));
			printf("# of FATs:           %u\n", vbr->numFATs);
			printf("Media descriptor:    %#x\n", vbr->mediaType);
			if (vi->extBootSig == 0x29) {
				u32 volumeID          = bswap32(vi->volumeID);
				printf("Filesystem type:     %.8s\n", vi->fsType);
				printf("Volume label:        %.11s\n", (memcmp(vi->volumeLabel, "NO NAME    ", 11) == 0 ? "<none>" : vi->volumeLabel));
				printf("Volume ID:           %04hX-%04hX\n", (u16)(volumeID >> 16), (u16)(volumeID));
			}
		} break;

		default:
			printf("Boot sector type: unknown (%i)\n", type);
			break;
	}
}


void show_sd_bsinfo(u32 sector) {
	u32 sector_data[0x80];

	if (!(sd_status() & SD_INITIALIZED)) {
		printf("SD card not initialized?");
		return;
	}

	int ret = sd_read(sector, 1, sector_data);
	if (ret < 0) {
		printf("sd_read failed (%i)\n", ret);
		return;
	}

	while (true) {
		clear();
		printf("Sector %#x (%u)\n\n", sector, sector);
		print_bsinfo(sector_data);

		printf("\n");
		switch (SelectionMenu("Show raw sector data", "(MBR) Show partition boot sector", "Back")) {
			case 1: {
				clear();
				printf("Sector data:\n");
				for (int i = 0; i < 0x80; i += 8)
					printf("%08x %08x %08x %08x %08x %08x %08x %08x\n",
						   sector_data[i+0], sector_data[i+1], sector_data[i+2], sector_data[i+3], sector_data[i+4], sector_data[i+5], sector_data[i+6], sector_data[i+7]);
			} break;

			case 2: {
				if (examine_bootsector(sector_data) != MBR) {
					puts("Boot sector type is not MBR.");
					break;
				}

				struct mbr* mbr = (struct mbr*)sector_data;

				int resp = SelectionMenu("Partition 1", "Partition 2", "Partition 3", "Partition 4", "Cancel");
				if (resp <= 0 || resp > 4)
					continue;

				MBRPartition* part = &mbr->partitions[resp - 1];
				if (!part->type) {
					puts("Partition does not exist(?)");
					break;
				}

				show_sd_bsinfo(bswap32(part->lba_start));
				continue;
			} break;

			default: {
				return;
			} break;
		}

		puts("\nPress any button to continue...");
		wait_button(0);
	}
}

// Thank you libdvm
void show_sd_fsinfo(void) {
	struct statvfs vfs = {};
	DvmDisc* disc = sd_dvm_init();

	if (!disc) {
		puts("sd_dvm_init() failed");
		return;
	}

	if (!dvmRegisterFsDriver(&g_vfatFsDriver)) {
		puts("dvmRegisterFsDriver failed");
	}

	int res = dvmProbeMountDisc("sd", disc);
	if (!res) {
		puts("dvmProbeMountDisc failed");
		return;
	}
	else {
		res = statvfs("sd:", &vfs);
		if (res < 0) {
			perror("statvfs");
		}
		else {
			printf("Cluster size:   %lu\n", vfs.f_bsize);
			printf("Total clusters: %llu (%lluMiB)\n", vfs.f_blocks, (vfs.f_blocks * vfs.f_bsize) >> 20);
			printf("Free clusters:  %llu (%lluMiB)\n", vfs.f_bfree, (vfs.f_bfree * vfs.f_bsize) >> 20);
		}
	}

	dvmUnmountVolume("sd:");
}

enum validrive_map {
	untested  = '\x20',
	data_ok   = '\xdb',
	data_bad  = '\xb0',
	read_err  = '\xb1',
	write_err = '\xb2',
};

void sd_test_validrive(void) {
	printf("=== Validrive test ===\n\n");

	char map[576] = {};

	// Arguments
	const u32  capacity = sd_capacity(),
	           capacity_mb = capacity >> (20 - 9),
	           split    = capacity / sizeof(map),
	           offset   = 2; // 3rd sector in every section

	printf("SD capacity: %u MiB (%#x/%u sectors)\n", capacity_mb, capacity, capacity);
	printf("%u sectors in %u sections; testing sector %u in each section\n\n", split, sizeof map, offset);

	if (capacity_mb % 1000 <= 1 && isPowerOfTwo(capacity_mb / 1000)) {
		printf("This SD card's capacity is a suspicious multiple of 1000.\n");
		printf("I don't trust it either.\n\n");
	}

	if (offset >= split) {
		printf("This SD card seems too small...\n");
		printf("(?????? Is this a <=256MB card???\?)\n");
		return;
	}

	if (sd_status() & SD_LOCKED) {
		printf("The SD card is locked.\n");
		printf("Check the slider on the left side of the SD card.\n");
		return;
	}

	printf("=== DISCLAIMER:\n");
	printf("Data retention is not guaranteed, I don't verify the old data\n");
	printf("after writing it back.\n\n");

	printf("If there's anything here that you care about: Back it up.\n\n");

	printf("Press +/START to begin test.\n");
	printf("Press any other button to cancel.\n");

	if (!(wait_button(0) & WPAD_BUTTON_PLUS))
		return;

	__attribute__((aligned(0x40)))
	static u32 test_data[0x80],
	           sector_data_r[0x80],
	           sector_data_w[0x80],
               sector_data_hash[5],
	           test_data_hash[5];

	int        read_errors = 0,
	           write_errors = 0,
	           good_sectors = 0,
               bad_sectors  = 0;


	clear();
	printf("Testing SD card (ValiDrive)...\n\n");

	// Clear map cause we're gonna be printing this to screen
	memset(map, untested, sizeof map);

	// Put in some data
	for (int i = 0; i < 0x10; i++) {
		test_data[i + 0x00] = 0x5555AAAA;
		test_data[i + 0x10] = 0xFFFFFFFF;
		test_data[i + 0x20] = 0x00000000;
		test_data[i + 0x30] = 0x11111111;
		test_data[i + 0x40] = 0x22222222;
		test_data[i + 0x50] = 0x44444444;
		test_data[i + 0x60] = 0x88888888;
		test_data[i + 0x70] = 0x12345678;
	}

	// And hash it. I am not going to memcmp a 512 byte block 576 times.
	if (SHA_Init() < 0 || AES_Init() < 0) {
		printf("SHA_Init() or AES_Init() failed, what is this, an old Dolphin emulator?\n");
		return;
	}

	// Should I encrypt it too? // Yes.
	u32 keydata[4];
	static char iv[16] __attribute__((aligned(4))) = "thepikachugamer";
	sd_decode_cid(keydata, 0);

	printf("keydata:        %08x%08x%08x%08x\n", keydata[0], keydata[1], keydata[2], keydata[3]);
	printf("iv:             %s\n", iv);

	AES_Encrypt(keydata, sizeof keydata, iv, sizeof iv, test_data, test_data, sizeof test_data);

	__attribute__((aligned(0x20))) // Libogc, why? It's an array of words that i'm pretty sure IOS writes to itself. I mean, look at the /dev/sha exploit. That doesn't data abort.
	sha_context ctx;
	SHA_InitializeContext(&ctx);
	SHA_Calculate(&ctx, test_data, sizeof test_data, test_data_hash);
	printf("test_data_hash: %08x%08x%08x%08x%08x\n", test_data_hash[0], test_data_hash[1], test_data_hash[2], test_data_hash[3], test_data_hash[4]);

	for (int i = 0; i < sizeof(map); i++) {
		u32 sector = (i * split) + offset;

		printf("\r Testing sector 0x%08x ... (%i/%i) ", sector, i + 1, sizeof(map));
		int ret = sd_read(sector, 1, sector_data_r);
		if (ret) {
			map[i] = read_err;
			read_errors++;
			continue;
		}

		ret = sd_write(sector, 1, test_data);
		if (ret) {
			map[i] = write_err;
			write_errors++;
			continue;
		}

		ret = sd_read(sector, 1, sector_data_w);
		if (ret) {
			map[i] = read_err;
			read_errors++;
			continue;
		}

		SHA_InitializeContext(&ctx);
		SHA_Calculate(&ctx, sector_data_w, sizeof sector_data_w, sector_data_hash);
		if (memcmp(sector_data_hash, test_data_hash, sizeof test_data_hash) == 0) {
			map[i] = data_ok;
			good_sectors++;
		}
		else {
			map[i] = data_bad;
			bad_sectors++;
		}

		ret = sd_write(sector, 1, sector_data_r);
		if (ret) {
			map[i] = write_err;
			write_errors++;
		}
	}

	clear();
	printf("Test results: \n");
	printf("+ Good sectors: %i\n", good_sectors);
	printf("+ Bad sectors:  %i\n", bad_sectors);
	printf("+ Read errors:  %i\n", read_errors);
	printf("+ Write errors: %i\n\n", write_errors);

	printf("Result map:\n");
	const int map_height = 9;
	const int map_width  = sizeof(map) / map_height;
	for (int i = 0; i < map_height; i++)
		printf("%.*s\n", map_width, map + (i * map_width));

	return;
}

int main(int argc, char **argv) {
	puts("Hello World!");

	initpads();
	sd_open();
	sd_init();
	/*
	if (ret < 0) {
		printf("sd_init() failed (%i)\n", ret);
		goto waitexit;
	}
	*/

	while (true) {
#if 0
		if (!(sd_status() & SD_INSERTED)) {
			clear();
			printf("Please insert an SD card...\n");
			printf("Press HOME to cancel.\n");
			while (!(sd_status() & SD_INSERTED)) {
				scanpads();
				if (buttons_down(WPAD_BUTTON_HOME))
					goto exit;

				usleep(200000);
			}
		}
#endif
		clear();
		printf("SD utils by thepikachugamer\n\n");

		switch (SelectionMenu("Show CID/CSD info", "Show boot sector info", "Show filesystem info", "Test SD card (ValiDrive)", "Press HOME to exit")) {
			case 1: {
				show_sd_cardinfo();
			} break;

			case 2: {
				show_sd_bsinfo(0);
				continue;
			} break;

			case 3: {
				show_sd_fsinfo();
			} break;

			case 4: {
				clear();
				sd_test_validrive();
			} break;

			default: {
				goto exit;
			} break;
		}

		puts("\nPress any button to continue...");
		wait_button(0);
	}

	puts("Press any button to exit.");
	wait_button(0);
exit:
	sd_close();
	return 0;
}
