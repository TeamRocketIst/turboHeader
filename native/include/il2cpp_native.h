#ifndef TURBOHEADER_IL2CPP_NATIVE_H
#define TURBOHEADER_IL2CPP_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *data;
    size_t size;
    char *error;
} I2CBlob;

/* offsets_path may be NULL/empty. pointer_size must be 4 or 8. */
I2CBlob i2c_parse_to_blob(const char *header_path, const char *offsets_path, int pointer_size);
void i2c_blob_free(I2CBlob *blob);

#ifdef __cplusplus
}
#endif
#endif
