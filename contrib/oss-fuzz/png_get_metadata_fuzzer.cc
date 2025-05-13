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

  png_bytep* row_pointers = (png_bytep*)malloc(sizeof(png_bytep) * height);
  for (png_uint_32 y = 0; y < height; y++) {
    row_pointers[y] = (png_bytep)malloc(png_get_rowbytes(png_ptr, info_ptr));
  }
  // Exploitation réelle des métadonnées

  //time
  png_timep mod_time_ptr = NULL;
  if (png_get_tIME(png_ptr, end_info_ptr, &mod_time_ptr)) {
      if (mod_time_ptr && mod_time_ptr->year > 2020) {
          volatile int y = mod_time_ptr->year;
      }
  }

  //text
  png_textp text_ptr;
  int num_text;
  if (png_get_text(png_ptr, info_ptr, &text_ptr, &num_text)) {
    if (num_text > 0 && text_ptr[0].text) {
      if (strstr(text_ptr[0].text, "meta")) {
        volatile char c = text_ptr[0].text[0];
      }
    }
  }

  //gama 
  double gamma;
  if (png_get_gAMA(png_ptr, info_ptr, &gamma)) {
    if (gamma > 0.5) {
      volatile int dummy = gamma * 100;
    }
  }

  //phys
  png_uint_32 res_x, res_y;
  int unit_type;
  if (png_get_pHYs(png_ptr, info_ptr, &res_x, &res_y, &unit_type)) {
      if (res_x > 300 && res_y > 300) {
          volatile int s = res_x + res_y + unit_type;
      }
  }

  //chrm 
  double w_x, w_y, r_x, r_y, g_x, g_y, b_x, b_y;

  if (png_get_cHRM(png_ptr, info_ptr,&w_x, &w_y,
                  &r_x, &r_y,
                  &g_x, &g_y,
                  &b_x, &b_y)) {
      volatile double sum = w_x + w_y + r_x + g_y;
  }

  //chrm xyz
  double red_X, red_Y, red_Z, green_X, green_Y, green_Z, blue_X, blue_Y, blue_Z;
  png_get_cHRM_XYZ(png_ptr, info_ptr, &red_X, &red_Y, &red_Z, &green_X, &green_Y, &green_Z, &blue_X, &blue_Y, &blue_Z);

  //chrm fixed
  png_fixed_point white_x, white_y, red_x, red_y, green_x, green_y, blue_x, blue_y;
  if (png_get_cHRM_fixed(png_ptr, info_ptr, &white_x, &white_y, &red_x, &red_y, &green_x, &green_y, &blue_x, &blue_y)) {
    if (white_x > 10000) {
      volatile int trigger = white_x + white_y + red_x; ;
    }
  }

  // chrm xyz fixed
  png_fixed_point ired_X, ired_Y, ired_Z, igreen_X, igreen_Y, igreen_Z, iblue_X, iblue_Y, iblue_Z;
  png_get_cHRM_XYZ_fixed(png_ptr, info_ptr, &ired_X, &ired_Y, &ired_Z, &igreen_X, &igreen_Y, &igreen_Z, &iblue_X, &iblue_Y, &iblue_Z);


  // sRGB
  int srgb_intent;
  if (png_get_sRGB(png_ptr, info_ptr, &srgb_intent)) {
      volatile int dummy = srgb_intent;
  }

  //sBIT
  png_color_8p sig_bits = NULL;

  if (png_get_sBIT(png_ptr, info_ptr, &sig_bits)) {
      // Use the significant bits to trigger instrumentation
      volatile int r = sig_bits->red;
      volatile int g = sig_bits->green;
      volatile int b = sig_bits->blue;
  }

  //bKGD
  png_color_16p background;

  if (png_get_bKGD(png_ptr, info_ptr, &background)) {
      // Access background color components (RGB version)
      volatile int r = background->red;
      volatile int g = background->green;
      volatile int b = background->blue;
  }

  //bKGD
  png_colorp palette = NULL;
  int num_palette = 0;

  if (png_get_PLTE(png_ptr, info_ptr, &palette, &num_palette)) {
      if (num_palette > 0 && palette != NULL) {
          // Access the first palette color (red, green, blue)
          volatile int r = palette[0].red;
          volatile int g = palette[0].green;
          volatile int b = palette[0].blue;
      }
  }

  /*png_uint_32 res_x, res_y;
  int unit_type;
  if (png_get_pHYs_dpi(png_ptr, info_ptr, &res_x, &res_y, &unit_type)) {
    if (res_x > 300 || res_y > 300) {
      volatile int d = res_x + res_y;
    }
  }

  int channels = png_get_channels(png_ptr, info_ptr);
  png_byte color_type2 = png_get_color_type(png_ptr, info_ptr);

  if (png_get_valid(png_ptr, info_ptr, PNG_INFO_tIME)) {
  volatile int flag = 1;
  }

  png_fixed_point gamma_fp;
  if (png_get_gAMA_fixed(png_ptr, info_ptr, &gamma_fp)) {
      if (gamma_fp > 4545) {
          volatile int d = gamma_fp;
      }
  }
  // hIST
  png_uint_16p hist = NULL;
  int num_palette = 0;
  png_colorp palette = NULL;
  png_get_PLTE(png_ptr, info_ptr, &palette, &num_palette); // Ensure palette is read
  if (num_palette > 0 && png_get_hIST(png_ptr, info_ptr, &hist)) {
      volatile int h = hist[0];
  }*/

  png_read_image(png_ptr, row_pointers);
  for (png_uint_32 y = 0; y < height; y++) {
    free(row_pointers[y]);
  }
  free(row_pointers);


  png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
  return 0;
}
