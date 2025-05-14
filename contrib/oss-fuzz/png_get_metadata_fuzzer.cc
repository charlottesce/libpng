#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>
#include <stdio.h>

#define PNG_INTERNAL
#include "png.h"

#include <vector>

#define PNG_CLEANUP \
  if(png_handler.png_ptr) \
  { \
    if (png_handler.row_ptr) \
      png_free(png_handler.png_ptr, png_handler.row_ptr); \
    if (png_handler.end_info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        &png_handler.end_info_ptr); \
    else if (png_handler.info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        nullptr); \
    else \
      png_destroy_read_struct(&png_handler.png_ptr, nullptr, nullptr); \
    png_handler.png_ptr = nullptr; \
    png_handler.row_ptr = nullptr; \
    png_handler.info_ptr = nullptr; \
    png_handler.end_info_ptr = nullptr; \
  }

struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};

struct PngObjectHandler {
  png_infop info_ptr = nullptr;
  png_structp png_ptr = nullptr;
  png_infop end_info_ptr = nullptr;
  png_voidp row_ptr = nullptr;
  BufState* buf_state = nullptr;

  ~PngObjectHandler() {
    if (row_ptr)
      png_free(png_ptr, row_ptr);
    if (end_info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    else if (info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    else
      png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    delete buf_state;
  }
};

void user_read_data(png_structp png_ptr, png_bytep data, size_t length) {
  BufState* buf_state = static_cast<BufState*>(png_get_io_ptr(png_ptr));
  if (length > buf_state->bytes_left) {
    png_error(png_ptr, "read error");
  }
  memcpy(data, buf_state->data, length);
  buf_state->bytes_left -= length;
  buf_state->data += length;
}

void* limited_malloc(png_structp, png_alloc_size_t size) {
  // libpng may allocate large amounts of memory that the fuzzer reports as
  // an error. In order to silence these errors, make libpng fail when trying
  // to allocate a large amount. This allocator used to be in the Chromium
  // version of this fuzzer.
  // This number is chosen to match the default png_user_chunk_malloc_max.
  if (size > 8000000)
    return nullptr;

  return malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  return free(ptr);
}

static const int kPngHeaderSize = 8;


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) {
    return 0;
  }

  std::vector<unsigned char> v(data, data + size);
  if (png_sig_cmp(v.data(), 0, kPngHeaderSize)) {
    // not a PNG.
    return 0;
  }
    PngObjectHandler png_handler;
  png_handler.png_ptr = nullptr;
  png_handler.row_ptr = nullptr;
  png_handler.info_ptr = nullptr;
  png_handler.end_info_ptr = nullptr;

  png_handler.png_ptr = png_create_read_struct
    (PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_handler.png_ptr) {
    return 0;
  }

  png_handler.info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.info_ptr) {
    PNG_CLEANUP
    return 0;
  }

  png_handler.end_info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.end_info_ptr) {
    PNG_CLEANUP
    return 0;
  }

  // Use a custom allocator that fails for large allocations to avoid OOM.
  png_set_mem_fn(png_handler.png_ptr, nullptr, limited_malloc, default_free);

  png_set_crc_action(png_handler.png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);

  // Setting up reading from buffer.
  png_handler.buf_state = new BufState();
  png_handler.buf_state->data = data + kPngHeaderSize;
  png_handler.buf_state->bytes_left = size - kPngHeaderSize;
  png_set_read_fn(png_handler.png_ptr, png_handler.buf_state, user_read_data);
  png_set_sig_bytes(png_handler.png_ptr, kPngHeaderSize);

  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }

  // Reading.
  png_read_info(png_handler.png_ptr, png_handler.info_ptr);

  // reset error handler to put png_deleter into scope.
  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }

  //PLTE -- does not work
  png_colorp palette = NULL;
  int num_palette = 0;

  if (png_get_PLTE(png_handler.png_ptr, png_handler.info_ptr, &palette, &num_palette)) {
      if (num_palette > 0 && palette != NULL) {
          // Access the first palette color (red, green, blue)
          volatile int r = palette[0].red;
          volatile int g = palette[0].green;
          volatile int b = palette[0].blue;
      }
  }

  // sRGB -- does not work 
  int srgb_intent;
  if (png_get_sRGB(png_handler.png_ptr, png_handler.info_ptr, &srgb_intent)!=0) {
      volatile int dummy = srgb_intent;
  }

  //sBIT --  does not work 
  png_color_8p sig_bits = NULL;
  if (png_get_sBIT(png_handler.png_ptr, png_handler.info_ptr, &sig_bits)) {
      // Use the significant bits to trigger instrumentation
      if (sig_bits != NULL) {
        volatile int r = sig_bits->red;
        volatile int g = sig_bits->green;
        volatile int b = sig_bits->blue;
      }
  }

  //bKGD -- does not work 
  png_color_16p background;

  if (png_get_bKGD(png_handler.png_ptr, png_handler.info_ptr, &background)) {
      // Access background color components (RGB version)
      volatile int r = background->red;
      volatile int g = background->green;
      volatile int b = background->blue;
  }

  // hIST
  png_uint_16p hist = NULL;
  if (num_palette > 0 && palette != NULL && png_get_hIST(png_handler.png_ptr, png_handler.info_ptr, &hist)) {
    volatile int h = hist[0];
  }

  //gama 
  double gamma;
  if (png_get_gAMA(png_handler.png_ptr, png_handler.info_ptr, &gamma)) {
    if (gamma > 0.5) {
      volatile int dummy = gamma * 100;
    }
  }

  //chrm fixed
  png_fixed_point white_x, white_y, red_x, red_y, green_x, green_y, blue_x, blue_y;
  if (png_get_cHRM_fixed(png_handler.png_ptr, png_handler.info_ptr, &white_x, &white_y, &red_x, &red_y, &green_x, &green_y, &blue_x, &blue_y)) {
    if (white_x > 10000) {
      volatile int trigger = white_x + white_y + red_x; ;
    }
  }

  // chrm xyz fixed
  png_fixed_point ired_X, ired_Y, ired_Z, igreen_X, igreen_Y, igreen_Z, iblue_X, iblue_Y, iblue_Z;
  png_get_cHRM_XYZ_fixed(png_handler.png_ptr, png_handler.info_ptr, &ired_X, &ired_Y, &ired_Z, &igreen_X, &igreen_Y, &igreen_Z, &iblue_X, &iblue_Y, &iblue_Z);

  //text
  png_textp text_ptr;
  int num_text;
  if (png_get_text(png_handler.png_ptr, png_handler.info_ptr, &text_ptr, &num_text)) {
    if (num_text > 0 && text_ptr[0].text) {
      if (strstr(text_ptr[0].text, "meta")) {
        volatile char c = text_ptr[0].text[0];
      }
    }
  }

  //phys
  png_uint_32 res_x, res_y;
  int unit_type;
  if (png_get_pHYs(png_handler.png_ptr, png_handler.info_ptr, &res_x, &res_y, &unit_type)) {
      if (res_x > 300 && res_y > 300) {
          volatile int s = res_x + res_y + unit_type;
      }
  }

  //gama fixed
  png_fixed_point gamma_fp;
  if (png_get_gAMA_fixed(png_handler.png_ptr, png_handler.info_ptr, &gamma_fp)) {
      if (gamma_fp > 4545) {
          volatile int d = gamma_fp;
      }
  }

  int bit_depth = png_get_bit_depth(png_handler.png_ptr, png_handler.info_ptr);
  volatile int bd = bit_depth;

  int filter_type = png_get_filter_type(png_handler.png_ptr, png_handler.info_ptr);
  volatile int ft = filter_type;

  int compression_type = png_get_compression_type(png_handler.png_ptr, png_handler.info_ptr);
  volatile int ct = compression_type;

  int interlace_type = png_get_interlace_type(png_handler.png_ptr, png_handler.info_ptr);
  volatile int it = interlace_type;

  png_uint_32 image_width = png_get_image_width(png_handler.png_ptr, png_handler.info_ptr);
  png_uint_32 image_height = png_get_image_height(png_handler.png_ptr, png_handler.info_ptr);
  volatile png_uint_32 dim = image_width + image_height;

  png_bytep trans = NULL;
  int num_trans = 0;
  png_color_16p trans_color = NULL;

  if (png_get_tRNS(png_handler.png_ptr, png_handler.info_ptr, &trans, &num_trans, &trans_color)) {
    if (trans != NULL) {
      volatile int alpha0 = trans[0];  // e.g., should be 0 for red
    }
  }

  png_charp profile_name = NULL;
  int iccp_compression_type = 0;
  png_bytep profile_data = NULL;
  png_uint_32 profile_len = 0;

  if (png_get_iCCP(png_handler.png_ptr, png_handler.info_ptr,
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

  if (png_get_sCAL_fixed(png_handler.png_ptr, png_handler.info_ptr, &unit, &scal_width, &scal_height)) {
      volatile int dummy_width = scal_width;
      volatile int dummy_heigth = scal_height;
  }

  png_unknown_chunkp unknown_chunks;
  int num_unknown = png_get_unknown_chunks(png_handler.png_ptr, png_handler.info_ptr, &unknown_chunks);

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
  png_get_IHDR(png_handler.png_ptr, png_handler.info_ptr, &width, &height, &bit_depth2, &color_type, nullptr, nullptr, nullptr);


  int channels = png_get_channels(png_handler.png_ptr, png_handler.info_ptr);
  png_byte color_type2 = png_get_color_type(png_handler.png_ptr, png_handler.info_ptr);


  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);
  
  png_handler.row_ptr = png_malloc(
      png_handler.png_ptr, png_get_rowbytes(png_handler.png_ptr,
                                            png_handler.info_ptr));

  
  for (png_uint_32 y = 0; y < height; ++y) {
    png_read_row(png_handler.png_ptr,
                  static_cast<png_bytep>(png_handler.row_ptr), nullptr);
  }

  png_read_end(png_handler.png_ptr, png_handler.end_info_ptr);


  //time
  png_timep mod_time_ptr = NULL;
  if (png_get_tIME(png_handler.png_ptr, png_handler.end_info_ptr, &mod_time_ptr)) {
      if (mod_time_ptr && mod_time_ptr->year > 2020) {
          volatile int y = mod_time_ptr->year;
      }
  }

  PNG_CLEANUP
  return 0;
}
