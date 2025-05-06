#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#define PNG_INTERNAL
#include "png.h"

static double read_double(const uint8_t **data, size_t *size) {
    if (*size < sizeof(double)) return 0.0;
    double val;
    memcpy(&val, *data, sizeof(double));
    *data += sizeof(double);
    *size -= sizeof(double);
    return val;
}

static size_t read_size_t(const uint8_t **data, size_t *size) {
    if (*size < sizeof(size_t)) return 0;
    size_t val;
    memcpy(&val, *data, sizeof(size_t));
    *data += sizeof(size_t);
    *size -= sizeof(size_t);
    return val;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png_ptr) return 0;

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, nullptr, nullptr);
        return 0;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
        return 0;
    }

    // 1️⃣ fuzz png_set_cHRM if enough data
    if (size >= sizeof(double) * 8) {
        double white_x = read_double(&data, &size);
        double white_y = read_double(&data, &size);
        double red_x   = read_double(&data, &size);
        double red_y   = read_double(&data, &size);
        double green_x = read_double(&data, &size);
        double green_y = read_double(&data, &size);
        double blue_x  = read_double(&data, &size);
        double blue_y  = read_double(&data, &size);

        png_set_cHRM(png_ptr, info_ptr, white_x, white_y, red_x, red_y, green_x, green_y, blue_x, blue_y);
    }

#ifdef PNG_iCCP_SUPPORTED
    // 2️⃣ fuzz png_set_iCCP if enough data
    if (size >= 4) {
        // Read a short string length
        size_t name_len = (*data % 32) + 1; // between 1 and 32 chars
        (*data)++;
        size--;

        if (size < name_len) name_len = size;
        std::string profile_name(reinterpret_cast<const char*>(data), name_len);
        data += name_len;
        size -= name_len;

        // Compression type: fuzzed or always PNG_COMPRESSION_TYPE_BASE
        int compression_type = PNG_COMPRESSION_TYPE_BASE;
        if (size >= 1) {
            compression_type = *data % 2 == 0 ? PNG_COMPRESSION_TYPE_BASE : 99; // 99 = invalid for edge cases
            data += 1;
            size -= 1;
        }

        // Read profile blob size
        size_t profile_len = (*data % 256) + 1; // 1-256 bytes
        (*data)++;
        size--;

        if (size < profile_len) profile_len = size;
        const uint8_t* profile_data = data;
        data += profile_len;
        size -= profile_len;

        png_set_iCCP(png_ptr, info_ptr, profile_name.c_str(), compression_type, profile_data, profile_len);
    }
#endif

    png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    return 0;
}
