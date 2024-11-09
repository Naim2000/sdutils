#include <gctypes.h>

struct cid {
	u8   manfid;
	u16  oemid;
	char name[5];
	union {
		u8 prv;
		struct { u8 hwrev: 4, fwrev: 4; };
	};
	u32  serial;
	u8   mdt_mon;
	u16  mdt_year;
};

// Thank you linux
struct csd {
	unsigned char		structure;
	unsigned short		cmdclass;
	unsigned short		taac_clks;
	unsigned int		taac_ns;
	unsigned int		c_size;
	unsigned int		c_size_mult;
	unsigned int		r2w_factor;
	unsigned int		max_dtr;
	unsigned int		erase_size;		/* In sectors */
	unsigned int		wp_grp_size;
	unsigned int		read_blkbits;
	unsigned int		write_blkbits;
	unsigned long long	capacity;
	unsigned int		read_partial:1,
						read_misalign:1,
						write_partial:1,
						write_misalign:1,
						dsr_imp:1,
						write_protect:2;
};

int sd_init(void);
int sd_close(void);

u32 sd_capacity(void);
int sd_read(u32 sector, u32 count, void* out);
int sd_write(u32 sector, u32 count, void* in);

void sd_decode_cid(u32* raw, struct cid*);
void sd_decode_csd(u32* raw, struct csd*);
