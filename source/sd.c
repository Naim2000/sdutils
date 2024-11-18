// Copyright 2008  Haxx Enterprises  <bushing@gmail.com>
// Copyright 2008-2009  Segher Boessenkool  <segher@kernel.crashing.org>
// This code is licensed to you under the terms of the GNU GPL, version 2;
// see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ogc/ipc.h>
#include <ogc/cache.h>

#include "sd.h"

#define SD_DEBUG 2
#define sd_printf(level, fmt, ...) do { if (level <= SD_DEBUG) printf("%s(): " fmt "\n", __FUNCTION__, ##__VA_ARGS__); } while (0);

static int fd = -1;

struct {
	union {
		u32 status;
		struct {
			u32         : 11;
			u32 sdhc    : 1;
			u32         : 3;
			u32 ready   : 1;
			u32         : 13;
			u32 locked  : 1;
			u32 absent  : 1;
			u32 inserted: 1;

		};
	};
	u32 rca;
	union {
		u32 scr_raw[2];
		struct {

		} scr;
	}; // Big endian system haha
	u32 ssr_raw[16];
	u32 cid_raw[4];
	u32 csd_raw[4];
	u32 capacity; // 512 byte blocks
} __attribute((aligned(4))) sdcard;

static int sd_hc_write8(u8 reg, u8 data)
{
	u32 param[6] = { [0] = reg, [3] = sizeof(u8), [4] = data };
	int err;

	err = IOS_Ioctl(fd, 1, param, sizeof param, 0, 0);

	return err;
}

static int sd_hc_read8(u8 reg, u8 *x)
{
	u32 param[6] = { [0] = reg, [3] = sizeof(u8), [4] = 0 };
	u32 data;
	int err;

	err = IOS_Ioctl(fd, 2, param, sizeof param, &data, sizeof data);
	if (err)
		return err;

	*x = data;

	return err;
}

static int sd_hc_getstatus(void)
{
	int err;
	u32 status;

	err = IOS_Ioctl(fd, 11, 0, 0, &status, sizeof status);
	if (err) {
		sd_printf(1, "%08x", err);
		return err;
	}

	sd_printf(3, "status=%08x", status);
	sdcard.status = status;
	return 0;
}

static int sd_reset_card(void)
{
	u32 reply = 0;
	int err;

	memset(&sdcard, 0, sizeof sdcard);

	err = IOS_Ioctl(fd, 4, 0, 0, &reply, sizeof reply);
	sd_printf(3, "%08x", reply);
	if (err)
		return err;

	sdcard.rca = reply & 0xffff0000;

	return 0;
}

static int sd_set_clock(void)
{
	u32 clock;
	int err;

	clock = 1;	// half of the sdclk divisor: a power of two or zero,
				// should look at capabilities reg to compute this

	err = IOS_Ioctl(fd, 6, &clock, sizeof clock, 0, 0);

	return err;
}

static int sd_command(u32 cmd, u32 cmd_type, u32 resp_type, u32 arg,
                      u32 block_count, u32 block_size, void *addr,
                      u32 *outreply, u32 reply_size)
{
	u32 param[9];
	u32 reply[4];
	int err;

	param[0] = cmd;
	param[1] = cmd_type;
	param[2] = resp_type;
	param[3] = arg;
	param[4] = block_count;
	param[5] = block_size;
	param[6] = (u32)addr;
	param[7] = 0; // ???
	param[8] = 0; // ???

	err = IOS_Ioctl(fd, 7, param, sizeof param, reply, sizeof reply);

	if (reply_size)
		memcpy(outreply, reply, reply_size);

	return err;
}


#define TYPE_BC 1
#define TYPE_BCR 2
#define TYPE_AC 3
#define TYPE_ADTC 4

#define RESPONSE_NONE 0
#define RESPONSE_R1 1
#define RESPONSE_R1B 2
#define RESPONSE_R2 3
#define RESPONSE_R3 4
#define RESPONSE_R4 5
#define RESPONSE_R5 6
#define RESPONSE_R6 7


static int sd_app_command(u32 cmd, u32 cmd_type, u32 resp_type, u32 arg,
                          u32 block_count, u32 block_size, void *addr,
                          u32 *outreply, u32 reply_size)
{
	int err;

	err = sd_command(55, TYPE_AC, RESPONSE_R1, sdcard.rca, 0, 0, 0, 0, 0);
	if (err)
		return err;

	if (cmd)
		err = sd_command(cmd, cmd_type, resp_type, arg,
                         block_count, block_size, addr,
                         outreply, reply_size);

	return err;
}

static int sd_data_command(u32 cmd, u32 cmd_type, u32 resp_type, u32 arg,
                           u32 block_count, u32 block_size, void *data,
                           u32 unk1, u32 unk2, u32 *outreply, u32 reply_size)
{
	u32 param[9];
	u32 reply[4];
	ioctlv vec[3];
	int err;

	param[0] = cmd;
	param[1] = cmd_type;
	param[2] = resp_type;
	param[3] = arg;
	param[4] = block_count;
	param[5] = block_size;
	param[6] = (u32)data;
	param[7] = unk1; // ???
	param[8] = unk2; // ???

	vec[0].data = param;
	vec[0].len = sizeof param;
	vec[1].data = data;
	vec[1].len = block_count * block_size;
	vec[2].data = reply;
	vec[2].len = sizeof reply;

	err = IOS_Ioctlv(fd, 7, 2, 1, vec);

	if (reply_size) // ???
		memcpy(outreply, reply, reply_size);

	return err;
}

// ???
static int sd_app_data_command(u32 cmd, u32 cmd_type, u32 resp_type, u32 arg,
                          u32 block_count, u32 block_size, void *addr,
                          u32 unk1, u32 unk2, u32 *outreply, u32 reply_size)
{
	int err;

	err = sd_command(55, TYPE_AC, RESPONSE_R1, sdcard.rca, 0, 0, 0, 0, 0);
	if (err)
		return err;

	err = sd_data_command(cmd, cmd_type, resp_type, arg,
                         block_count, block_size, addr,
                         unk1, unk2, outreply, reply_size);

	return err;
}

static int sd_select(void)
{
	int err;

	err = sd_command(7, TYPE_AC, RESPONSE_R1B, sdcard.rca, 0, 0, 0, 0, 0);
	if (err)
		sd_printf(2, "%08x", err);

	return err;
}

static int sd_deselect(void)
{
	int err;

	err = sd_command(7, TYPE_AC, RESPONSE_R1B, 0, 0, 0, 0, 0, 0);

	return err;
}

static inline u32 unstuff_bits(const u32 *resp, int start, int size)
{
	const int __start = (start - 8) & 127; // Hack 1
	const int __size = size;
	const u32 __mask = (1 << __size) - 1;
	const int __off = (__start / 32); // Hack 2
	const int __shft = __start & 31;
	u32 __res = resp[__off] >> __shft;

	if (__size + __shft > 32)
		__res |= resp[__off + 1] << ((32 - __shft) % 32);

	return __res & __mask;
}

static int sd_send_csd(void)
{
	int err;

	err = sd_command(9, TYPE_AC, RESPONSE_R2, sdcard.rca, 0, 0, 0, sdcard.csd_raw, 16);
	if (err) {
		sd_printf(1, "%08x", err);
		return err;
	}
	sd_printf(2, "CSD: %08x%08x%08x%08x", sdcard.csd_raw[3], sdcard.csd_raw[2], sdcard.csd_raw[1], sdcard.csd_raw[0]);

	return 0;
}

static int sd_send_cid(void)
{
	int err;

	err = sd_command(10, TYPE_AC, RESPONSE_R2, sdcard.rca, 0, 0, 0, sdcard.cid_raw, 16);
	if (err) {
		sd_printf(1, "%08x", err);
		return err;
	}
	sd_printf(2, "CID: %08x%08x%08x%08x", sdcard.cid_raw[3], sdcard.cid_raw[2], sdcard.cid_raw[1], sdcard.cid_raw[0]);

	return 0;
}

static int sd_send_scr(void) {
	int err;
	u32 resp[4] = {};

	err = sd_app_data_command(51, TYPE_ADTC, RESPONSE_R1, sdcard.rca, 1, sizeof sdcard.scr_raw, sdcard.scr_raw, 0, 0, resp, sizeof resp);

	if (err) {
		sd_printf(1, "err=%08x resp=%08x", err, resp[0]);
		return err;
	}

	DCInvalidateRange(sdcard.scr_raw, sizeof sdcard.scr_raw);
	sd_printf(2, "scr=%08x%08x", sdcard.scr_raw[0], sdcard.scr_raw[1]);
	return err;
}

static int sd_send_ssr(void) {
	int err;
	u32 resp[4] = {};

	err = sd_app_data_command(13, TYPE_ADTC, RESPONSE_R1, sdcard.rca, 1, sizeof sdcard.ssr_raw, sdcard.ssr_raw, 0, 0, resp, sizeof resp);

	if (err) {
		sd_printf(1, "err=%08x resp=%08x", err, resp[0]);
		return err;
	}

	DCInvalidateRange(sdcard.ssr_raw, sizeof sdcard.ssr_raw);
	sd_printf(2, "SD Status register:");
	for (int i = 0; i < 0x10; i += 4) {
		sd_printf(2, "%08x %08x %08x %08x", sdcard.ssr_raw[i+0], sdcard.ssr_raw[i+1], sdcard.ssr_raw[i+2], sdcard.ssr_raw[i+3]);
	}
	return err;
}

void sd_decode_csd(u32* raw, struct csd* csd)
{
	static const unsigned int tran_exp[] = {
		10000,		100000,		1000000,	10000000,
		0,		0,		0,		0
	};

	static const unsigned char tran_mant[] = {
		0,	10,	12,	13,	15,	20,	25,	30,
		35,	40,	45,	50,	55,	60,	70,	80,
	};

	static const unsigned int taac_exp[] = {
		1,	10,	100,	1000,	10000,	100000,	1000000, 10000000,
	};

	static const unsigned int taac_mant[] = {
		0,	10,	12,	13,	15,	20,	25,	30,
		35,	40,	45,	50,	55,	60,	70,	80,
	};

	u32* csd_raw = sdcard.csd_raw;

	if (raw) {
		memcpy(raw, csd_raw, 0x10);
	}

	if (csd) {
		unsigned int e, m;
		csd->structure = unstuff_bits(csd_raw, 126, 2);

		switch (csd->structure) {
		case 0:
			m = unstuff_bits(csd_raw, 115, 4);
			e = unstuff_bits(csd_raw, 112, 3);
			csd->taac_ns	 = (taac_exp[e] * taac_mant[m] + 9) / 10;
			csd->taac_clks	 = unstuff_bits(csd_raw, 104, 8) * 100;

			m = unstuff_bits(csd_raw, 99, 4);
			e = unstuff_bits(csd_raw, 96, 3);
			csd->max_dtr	  = tran_exp[e] * tran_mant[m];
			csd->cmdclass	  = unstuff_bits(csd_raw, 84, 12);

			csd->c_size = m = unstuff_bits(csd_raw, 62, 12);
			csd->c_size_mult = e = unstuff_bits(csd_raw, 47, 3);
			csd->capacity = (1 + m) << (e + 2);

			csd->read_blkbits = unstuff_bits(csd_raw, 80, 4);
			csd->read_partial = unstuff_bits(csd_raw, 79, 1);
			csd->write_misalign = unstuff_bits(csd_raw, 78, 1);
			csd->read_misalign = unstuff_bits(csd_raw, 77, 1);
			csd->dsr_imp = unstuff_bits(csd_raw, 76, 1);
			csd->r2w_factor = unstuff_bits(csd_raw, 26, 3);
			csd->write_blkbits = unstuff_bits(csd_raw, 22, 4);
			csd->write_partial = unstuff_bits(csd_raw, 21, 1);

			if (csd->read_blkbits > 9) {
				csd->capacity <<= csd->read_blkbits - 9;
			}

			if (unstuff_bits(csd_raw, 46, 1)) {
				csd->erase_size = 1;
			} else if (csd->write_blkbits >= 9) {
				csd->erase_size = unstuff_bits(csd_raw, 39, 7) + 1;
				csd->erase_size <<= csd->write_blkbits - 9;
			}

			csd->write_protect = unstuff_bits(csd_raw, 12, 2);
			break;
		case 1:
			/*
			* This is a block-addressed SDHC or SDXC card. Most
			* interesting fields are unused and have fixed
			* values. To avoid getting tripped by buggy cards,
			* we assume those fixed values ourselves.
			*/

			csd->taac_ns	 = 0; /* Unused */
			csd->taac_clks	 = 0; /* Unused */

			m = unstuff_bits(csd_raw, 99, 4);
			e = unstuff_bits(csd_raw, 96, 3);
			csd->max_dtr	= tran_exp[e] * tran_mant[m];
			csd->cmdclass	= unstuff_bits(csd_raw, 84, 12);
			csd->c_size		= unstuff_bits(csd_raw, 48, 22);

			csd->capacity     = (csd->c_size + 1) << 10;

			csd->read_blkbits = 9;
			csd->read_partial = 0;
			csd->write_misalign = 0;
			csd->read_misalign = 0;
			csd->r2w_factor = 4; /* Unused */
			csd->write_blkbits = 9;
			csd->write_partial = 0;
			csd->erase_size = 1;

			csd->write_protect = unstuff_bits(csd_raw, 12, 2);
			break;
		default:
			sd_printf(1, "unrecognised CSD structure version %d", csd->structure);
		}
	}

}

void sd_decode_cid(u32* cid_raw, struct cid* cid) {
	if (cid_raw) {
		memcpy(cid_raw, sdcard.cid_raw, 0x10);
	}

	if (cid) {
		memset(cid, 0, sizeof(struct cid));

		cid->manfid   = unstuff_bits(sdcard.cid_raw, 120, 8);
		cid->oemid    = unstuff_bits(sdcard.cid_raw, 104, 16);
		cid->name[0]  = unstuff_bits(sdcard.cid_raw, 96, 8);
		cid->name[1]  = unstuff_bits(sdcard.cid_raw, 88, 8);
		cid->name[2]  = unstuff_bits(sdcard.cid_raw, 80, 8);
		cid->name[3]  = unstuff_bits(sdcard.cid_raw, 72, 8);
		cid->name[4]  = unstuff_bits(sdcard.cid_raw, 64, 8);
		cid->hwrev    = unstuff_bits(sdcard.cid_raw, 60, 4);
		cid->fwrev    = unstuff_bits(sdcard.cid_raw, 56, 4);
		cid->serial   = unstuff_bits(sdcard.cid_raw, 24, 32);
		cid->mdt_year = unstuff_bits(sdcard.cid_raw, 12, 8) + 2000;
		cid->mdt_mon  = unstuff_bits(sdcard.cid_raw, 8, 4);
	}

}

static int sd_set_blocklength(u32 len)
{
	int err;

	err = sd_command(16, TYPE_AC, RESPONSE_R1, len, 0, 0, 0, 0, 0);

	return err;
}

static int sd_set_bus_width(int width)
{
	u32 arg;
	u8 reg;
	int err;

	// First notify the card.
	arg = (width == 4) ? 2 : 0;

	err = sd_app_command(6, TYPE_AC, RESPONSE_R1, arg, 0, 0, 0, 0, 0);
	if (err)
		return err;

	// Now change the Host Control Register.
	err = sd_hc_read8(0x28, &reg);
	if (err)
		return err;

	reg = (reg & ~2) | arg;

	err = sd_hc_write8(0x28, reg);

	return err;
}

int sd_read(u32 sector, u32 count, void* out)
{
	u32 reply[4];
	int err;

	if (count == 0)
		return -1;

	err = sd_select();
	if (err)
		return err;

	u32 addr = sector;
	if (!sdcard.sdhc)
		addr <<= 9; // * 2^9 (512)

	err = sd_data_command(18, TYPE_AC, RESPONSE_R1, addr,
	                      count, 0x200, out, 1, 0, reply, sizeof reply);

	if (err)
		sd_printf(0, "SD READ lba=%08x, err=%08x, reply=%08x",
		       sector, err, reply[0]);

	sd_deselect();
	return err;
}

int sd_write(u32 sector, u32 count, void* in)
{
	u32 reply[4];
	int err;

	if (count == 0) // ?
		return -1;

	if (sdcard.locked) {
		sd_printf(0, "\x1b[41m The SD card is locked. \x1b[40m");
	}

	err = sd_select();
	if (err)
		return err;

	u32 addr = sector;
	if (!sdcard.sdhc)
		addr <<= 9; // * 2^9 (512)

	err = sd_data_command(25, TYPE_AC, RESPONSE_R1, addr,
	                      count, 0x200, in, 1, 0, reply, sizeof reply);

	if (err)
		sd_printf(0, "SD WRITE lba=%08x, err=%08x, reply=%08x",
		       sector, err, reply[0]);

	sd_deselect();
	return err;
}

u32 sd_capacity(void)
{
	struct csd csd;

	sd_decode_csd(0, &csd);
	return csd.capacity;
}

static int sd_register_event(int ev);

static int sd_event_cb(int res, __attribute__((unused)) void* userdata) {
	sd_printf(1, "event %#x fired", res);
	switch (res) {
		case 1: { // Insert
			usleep(200000);
			sd_init();
		} break;

		case 2: { // Remove
			memset(&sdcard, 0, sizeof sdcard);
		} break;

		default:
			sd_printf(0, "unknown event %#x", res);
		case 0: // Cancelled
			return 0;
		break;
	}

	sd_register_event((res & 0x3) ^ 0x3);
	return 0;
}

static int sd_register_event(int ev) {
	static u32 cmd[9];

	cmd[0] = 0x40 + (ev == 0);
	cmd[3] = ev;

	sd_printf(1, "%#x", ev);
	return IOS_IoctlAsync(fd, 7, cmd, sizeof cmd, 0, 0, sd_event_cb, 0);
}

int sd_open(void) {
	if (fd < 0) {
		int err = fd = IOS_Open("/dev/sdio/slot0", 0);
		if (err < 0)
			return err;

		sd_hc_getstatus();

		sd_register_event(sdcard.inserted ? 2 : 1);
	}

	return 0;
}

int sd_close(void)
{
	int err = 0;

	memset(&sdcard, 0, sizeof sdcard);
	if (fd >= 0) {
		sd_register_event(0);

		err = IOS_Close(fd);
		fd = -1;
	}

	return err;
}

int sd_init(void)
{
	int err;

	err = sd_open();
	if (err)
		return err;

	err = sd_reset_card();
	sd_hc_getstatus();

	if (!sdcard.inserted) {
		sd_printf(0, "SD card not present");
		goto out;
	}

	if (!sdcard.ready) {
		sd_printf(0, "SD card not initialized (%08x)", err);
		goto out;
	}

	if (sdcard.locked) {
		sd_printf(0, "(The SD card is locked.)");
	}

	err = sd_send_cid();
	if (err)
		goto out;

	err = sd_send_csd();
	if (err)
		goto out;

	err = sd_select();
	if (err)
		goto out;

	// now in transfer state

	// Some broken cards require this:
	err = sd_set_blocklength(0x200);
	if (err)
		goto out;

	err = sd_set_bus_width(4);	// XXX: Should check in SCR first. // Well, all SD cards are supposed to support at least 1 bit & 4 bit mode
	if (err)
		goto out;

	err = sd_set_clock();	// XXX: Should check.
	if (err)
		goto out;

	err = sd_send_scr();
	if (err)
		goto out;

	sd_select();

	err = sd_send_ssr();
	if (err)
		goto out;

	sd_deselect();



	return 0;
out:
	sd_deselect();
	// sd_close();

	return err ?: -1;
}

int sd_status(void) {
	sd_hc_getstatus();
	return sdcard.status & (SD_INSERTED | SD_REMOVED | SD_LOCKED | SD_INITIALIZED);
}
