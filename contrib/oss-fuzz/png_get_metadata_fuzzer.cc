#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 8 || !png_check_sig(data, 8)) {
    return 0;
  }

  png_image image;
  memset(&image, 0, sizeof image);
  image.version = PNG_IMAGE_VERSION;

  if (!png_image_begin_read_from_memory(&image, data, size)) {
    return 0;
  }

  png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (!png_ptr) return 0;
  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_read_struct(&png_ptr, NULL, NULL);
    return 0;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    return 0;
  }

  const uint8_t* data_ptr = data;
  png_set_read_fn(png_ptr, (png_voidp)&data_ptr, [](png_structp png_ptr, png_bytep outBytes, png_size_t byteCountToRead) {
    const uint8_t** input = (const uint8_t**)png_get_io_ptr(png_ptr);
    memcpy(outBytes, *input, byteCountToRead);
    *input += byteCountToRead;
  });

  png_read_info(png_ptr, info_ptr);

  // 🔍 Appels à tes fonctions png_get_*
  png_timep mod_time;
  png_get_tIME(png_ptr, info_ptr, &mod_time);

  png_textp text_ptr;
  int num_text;
  png_get_text(png_ptr, info_ptr, &text_ptr, &num_text);

  double gamma;
  int gamma_result = png_get_gAMA(png_ptr, info_ptr, &gamma);

  png_uint_32 res_x, res_y;
  int unit_type;
  png_get_pHYs(png_ptr, info_ptr, &res_x, &res_y, &unit_type);

  png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
  return 0;
}
