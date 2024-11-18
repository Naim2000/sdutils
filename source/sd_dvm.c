#include <stdlib.h>

#include "sd.h"
#include "sd_dvm.h"

static void _sd_dvm_destroy(DvmDisc* self) {
    self->num_sectors = -1;
}

static bool _sd_dvm_read(DvmDisc* self, void* buffer, sec_t sector, sec_t count) {
    return !sd_read(sector, count, buffer);
}

static bool _sd_dvm_write(DvmDisc* self, const void* buffer, sec_t sector, sec_t count) {
    return !sd_write(sector, count, (void*) buffer);
}

static void _sd_dvm_flush(DvmDisc* self) {

}

static DvmDiscIface _sd_dvm_iface = {
    .destroy       = _sd_dvm_destroy,
    .read_sectors  = _sd_dvm_read,
    .write_sectors = _sd_dvm_write,
    .flush         = _sd_dvm_flush,
};

static DvmDisc sd_dvm = {
    .vt       = &_sd_dvm_iface,
    .io_type  = ('s' << 24 | 'd' << 16 | 'm' << 8 | 'c' << 0),
    .features = (FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE | FEATURE_WII_SD),
};

DvmDisc* sd_dvm_init(void) {
    if (sd_status() & SD_INITIALIZED) {
        struct csd csd;
        sd_decode_csd(0, &csd);

        sd_dvm.num_sectors = csd.capacity;
        return &sd_dvm;
    }

    return NULL;
}
