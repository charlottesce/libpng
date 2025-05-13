#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 8 || !png_check_sig(data, 8)) {
    return 0;
  }

  png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (!png_ptr) return 0;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  png_infop end_info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr || !end_info_ptr) {
    png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    return 0;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    return 0;
  }

  const uint8_t* data_ptr = data;
  png_set_read_fn(png_ptr, (png_voidp)&data_ptr,
    [](png_structp png_ptr, png_bytep outBytes, png_size_t byteCountToRead) {
      const uint8_t** input = (const uint8_t**)png_get_io_ptr(png_ptr);
      memcpy(outBytes, *input, byteCountToRead);
      *input += byteCountToRead;
    });

  png_set_sig_bytes(png_ptr, 8);
  png_read_info(png_ptr, info_ptr);

  // Lire une ligne
  png_uint_32 width, height;
  int bit_depth, color_type;
  png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth, &color_type, nullptr, nullptr, nullptr);

  png_read_update_info(png_ptr, info_ptr);
  png_bytep row = (png_bytep)malloc(png_get_rowbytes(png_ptr, info_ptr));
  if (row && height > 0) {
    png_read_row(png_ptr, row, NULL);
  }
  free(row);

  png_read_end(png_ptr, end_info_ptr);

  // 🔍 Exploitation réelle des métadonnées
  png_timep mod_time;
  if (png_get_tIME(png_ptr, end_info_ptr, &mod_time)) {
    if (mod_time->year > 2020) {
      volatile int y = mod_time->year;
    }
  }

  png_textp text_ptr;
  int num_text;
  if (png_get_text(png_ptr, info_ptr, &text_ptr, &num_text)) {
    if (num_text > 0 && text_ptr[0].text) {
      if (strstr(text_ptr[0].text, "meta")) {
        volatile char c = text_ptr[0].text[0];
      }
    }
  }

  double gamma;
  if (png_get_gAMA(png_ptr, info_ptr, &gamma)) {
    if (gamma > 0.5) {
      volatile int dummy = gamma * 100;
    }
  }

  png_uint_32 res_x, res_y;
  int unit_type;
  if (png_get_pHYs(png_ptr, info_ptr, &res_x, &res_y, &unit_type)) {
    if (res_x > 300 && res_y > 300) {
      volatile int d = res_x + res_y;
    }
  }

  png_fixed_point white_x, white_y, red_x, red_y, green_x, green_y, blue_x, blue_y;
  if (png_get_cHRM_fixed(png_ptr, info_ptr, &white_x, &white_y, &red_x, &red_y, &green_x, &green_y, &blue_x, &blue_y)) {
    if (white_x > 10000) {
      volatile int dummy = white_x;
    }
  }

  png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
  return 0;
}
