typedef struct fatvbr fatvbr;

struct __attribute__((packed)) fatvbr {
    u8   jmpBoot[3];
    char oemName[8];
    u16  bytesPerSector;
    u8   sectorsPerCluster;
    u16  fatStart;
    u8   numFATs;
    u16  rootEntries;
    u16  totalSectors16;
    u8   mediaType;
    u16  sectorsPerFAT;
    u16  sectorsPerTrack;
    u16  numHeads;
    u32  numHiddenSectors;
    u32  totalSectors32;
    union {
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
};
