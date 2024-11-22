typedef union CHS CHS;
typedef struct MBRPartition MBRPartition;
typedef struct MBR MBR;

union __attribute__((packed)) CHS {
	u8 chs8[3];
	u32 chs24: 24;
	struct {
		u8 head;
		u8 cylinder_h: 2;
		u8 sector: 6;
		u8 cylinder_l;
	};
};

enum MBRPartitionType: u8 {
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
};

struct __attribute__((packed)) MBRPartition {
	u8  status;
	CHS chs_start;
	u8  type;
	CHS chs_end;
	u32 lba_start;
	u32 lba_count;
};
_Static_assert(sizeof(MBRPartition) == 0x10, "MBRPartition size incorrect");

struct MBR {
    u8           code[0x1B8];
    u32          disk_sig;
    u16          copyflag;
    MBRPartition partitions[4];
    u16          boot_sig;
};
_Static_assert(offsetof(MBR, partitions) == 0x1BE, "MBR partition table offset incorrect");
_Static_assert(sizeof(MBR) == 0x200, "MBR size incorrect");
