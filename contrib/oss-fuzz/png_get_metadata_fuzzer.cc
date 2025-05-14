#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>
#include <stdio.h>

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

  //PLTE -- does not work
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

  // sRGB -- does not work 
  int srgb_intent;
  if (png_get_sRGB(png_ptr, info_ptr, &srgb_intent)!=0) {
      volatile int dummy = srgb_intent;
  }

  //sBIT --  does not work 
  png_color_8p sig_bits = NULL;
  if (png_get_sBIT(png_ptr, info_ptr, &sig_bits)) {
      // Use the significant bits to trigger instrumentation
      volatile int r = sig_bits->red;
      volatile int g = sig_bits->green;
      volatile int b = sig_bits->blue;
  }

  //bKGD -- does not work 
  png_color_16p background;

  if (png_get_bKGD(png_ptr, info_ptr, &background)) {
      // Access background color components (RGB version)
      volatile int r = background->red;
      volatile int g = background->green;
      volatile int b = background->blue;
  }

  // hIST
  png_uint_16p hist = NULL;
  if (num_palette > 0 && palette != NULL && png_get_hIST(png_ptr, info_ptr, &hist)) {
    volatile int h = hist[0];
  }

  //gama 
  double gamma;
  if (png_get_gAMA(png_ptr, info_ptr, &gamma)) {
    if (gamma > 0.5) {
      volatile int dummy = gamma * 100;
    }
  }

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

  //phys
  png_uint_32 res_x, res_y;
  int unit_type;
  if (png_get_pHYs(png_ptr, info_ptr, &res_x, &res_y, &unit_type)) {
      if (res_x > 300 && res_y > 300) {
          volatile int s = res_x + res_y + unit_type;
      }
  }

  //gama fixed
  png_fixed_point gamma_fp;
  if (png_get_gAMA_fixed(png_ptr, info_ptr, &gamma_fp)) {
      if (gamma_fp > 4545) {
          volatile int d = gamma_fp;
      }
  }

  int bit_depth = png_get_bit_depth(png_ptr, info_ptr);
  volatile int bd = bit_depth;

  int filter_type = png_get_filter_type(png_ptr, info_ptr);
  volatile int ft = filter_type;

  int compression_type = png_get_compression_type(png_ptr, info_ptr);
  volatile int ct = compression_type;

  int interlace_type = png_get_interlace_type(png_ptr, info_ptr);
  volatile int it = interlace_type;

  png_uint_32 image_width = png_get_image_width(png_ptr, info_ptr);
  png_uint_32 image_height = png_get_image_height(png_ptr, info_ptr);
  volatile png_uint_32 dim = image_width + image_height;

  png_bytep trans = NULL;
  int num_trans = 0;
  png_color_16p trans_color = NULL;

  if (png_get_tRNS(png_ptr, info_ptr, &trans, &num_trans, &trans_color)) {
      volatile int alpha0 = trans[0];  // e.g., should be 0 for red
  }

  png_charp profile_name = NULL;
  int iccp_compression_type = 0;
  png_bytep profile_data = NULL;
  png_uint_32 profile_len = 0;

  if (png_get_iCCP(png_ptr, info_ptr,
                  &profile_name,
                  &iccp_compression_type,
                  &profile_data,
                  &profile_len)) {
      // Example access to trigger coverage
      if (profile_len > 0 && profile_data != NULL) {
          volatile char first_byte = profile_data[0];
      }
      volatile int name_len = strlen(profile_name);
      volatile int len = profile_len;
  }

  png_fixed_point scal_width, scal_height;
  int unit;

  if (png_get_sCAL_fixed(png_ptr, info_ptr, &unit, &scal_width, &scal_height)) {
      printf("Width: %d\n", scal_width);
      printf("Height: %d\n", scal_height);
  }

  png_unknown_chunkp unknown_chunks;
  int num_unknown = png_get_unknown_chunks(png_ptr, info_ptr, &unknown_chunks);

  if (num_unknown > 0) {
      for (int i = 0; i < num_unknown; i++) {
          png_unknown_chunkp chunk = &unknown_chunks[i];

          // Access fields
          volatile int length = chunk->size;
          volatile char first_byte = chunk->data[0];
          volatile char chunk_name0 = chunk->name[0];
          volatile char chunk_name1 = chunk->name[1];
          volatile char chunk_name2 = chunk->name[2];
          volatile char chunk_name3 = chunk->name[3];
      }
  }

  // Lire une ligne
  png_uint_32 width, height;
  int bit_depth2, color_type;
  png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth2, &color_type, nullptr, nullptr, nullptr);


  int channels = png_get_channels(png_ptr, info_ptr);
  png_byte color_type2 = png_get_color_type(png_ptr, info_ptr);


  png_read_update_info(png_ptr, info_ptr);
  png_bytep row = (png_bytep)malloc(png_get_rowbytes(png_ptr, info_ptr));
  if (row && height > 0) {
    png_read_row(png_ptr, row, NULL);
  }
  free(row);

  png_bytep* row_pointers = (png_bytep*)malloc(sizeof(png_bytep) * height);
  for (png_uint_32 y = 0; y < height; y++) {
    row_pointers[y] = (png_bytep)malloc(png_get_rowbytes(png_ptr, info_ptr));
  }
  png_read_image(png_ptr, row_pointers);
  for (png_uint_32 y = 0; y < height; y++) {
    free(row_pointers[y]);
  }
  free(row_pointers);

  png_read_end(png_ptr, end_info_ptr);


  //time
  png_timep mod_time_ptr = NULL;
  if (png_get_tIME(png_ptr, end_info_ptr, &mod_time_ptr)) {
      if (mod_time_ptr && mod_time_ptr->year > 2020) {
          volatile int y = mod_time_ptr->year;
      }
  }


  png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
  return 0;
}
