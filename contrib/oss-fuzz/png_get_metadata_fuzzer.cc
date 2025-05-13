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
  png_infop end_info_ptr = png_create_info_struct(png_ptr);  // Important pour lire les metadata de fin
  if (!info_ptr || !end_info_ptr) {
    png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    return 0;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    return 0;
  }

  const uint8_t* data_ptr = data;
  size_t data_left = size;

  png_set_read_fn(png_ptr, (png_voidp)&data_ptr,
    [](png_structp png_ptr, png_bytep outBytes, png_size_t byteCountToRead) {
      const uint8_t** input = (const uint8_t**)png_get_io_ptr(png_ptr);
      memcpy(outBytes, *input, byteCountToRead);
      *input += byteCountToRead;
    });

  png_set_sig_bytes(png_ptr, 8);  // Nous avons déjà vérifié la signature
  png_read_info(png_ptr, info_ptr);

  // Lire au moins une ligne de données pour forcer le parsing du contenu
  png_uint_32 width, height;
  int bit_depth, color_type;
  png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth, &color_type, nullptr, nullptr, nullptr);

  png_read_update_info(png_ptr, info_ptr);
  png_bytep row = (png_bytep)malloc(png_get_rowbytes(png_ptr, info_ptr));
  if (row && height > 0) {
    png_read_row(png_ptr, row, NULL);
  }

  free(row);

  // Lire la fin pour forcer les chunks comme tIME, pHYs, etc.
  png_read_end(png_ptr, end_info_ptr);

  // Extraire les metadata (maintenant que la lecture est complète)
  png_timep mod_time;
  png_get_tIME(png_ptr, end_info_ptr, &mod_time);  // Doit être fait sur end_info_ptr

  png_textp text_ptr;
  int num_text;
  png_get_text(png_ptr, info_ptr, &text_ptr, &num_text);

  double gamma;
  png_get_gAMA(png_ptr, info_ptr, &gamma);

  png_uint_32 res_x, res_y;
  int unit_type;
  png_get_pHYs(png_ptr, info_ptr, &res_x, &res_y, &unit_type);

  png_fixed_point white_x, white_y, red_x, red_y, green_x, green_y, blue_x, blue_y;
  png_get_cHRM_fixed(png_ptr, info_ptr, &white_x, &white_y, &red_x, &red_y, &green_x, &green_y, &blue_x, &blue_y);

  png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
  return 0;
}
