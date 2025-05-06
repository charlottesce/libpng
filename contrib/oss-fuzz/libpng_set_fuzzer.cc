#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h> // For isfinite

#include "png.h"

// Define a structure to hold the PNG info pointer
struct PngInfoWrapper {
  png_infop info_ptr = nullptr;
  png_structp png_ptr = nullptr;

  PngInfoWrapper() {
    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (png_ptr) {
      info_ptr = png_create_info_struct(png_ptr);
    }
  }

  ~PngInfoWrapper() {
    if (png_ptr && info_ptr) {
      png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    } else if (png_ptr) {
      png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    }
  }
};

// Helper function to safely convert a portion of the fuzzer input to a double
static double safe_double(const uint8_t* data, size_t offset, size_t size) {
  if (offset + sizeof(double) > size) {
    return NAN; // Or some other sentinel value
  }
  double value;
  memcpy(&value, data + offset, sizeof(double));
  // Ensure the value is somewhat reasonable to avoid extreme inputs
  if (!isfinite(value)) {
    return NAN;
  }
  return value;
}

// Helper function to safely get a fixed point value
static png_fixed_point safe_fixed(const uint8_t* data, size_t offset, size_t size) {
  if (offset + sizeof(png_fixed_point) > size) {
    return 0; // Or some other default
  }
  png_fixed_point value;
  memcpy(&value, data + offset, sizeof(png_fixed_point));
  return value;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < sizeof(double) * 8) { // Need enough data for the cHRM parameters
    return 0;
  }

  PngInfoWrapper png_info_wrapper;
  png_structp png_ptr = png_info_wrapper.png_ptr;
  png_infop info_ptr = png_info_wrapper.info_ptr;

  if (!png_ptr || !info_ptr) {
    return 0;
  }

  // Extract parameters for png_set_cHRM
  double white_x = safe_double(data, 0 * sizeof(double), size);
  double white_y = safe_double(data, 1 * sizeof(double), size);
  double red_x = safe_double(data, 2 * sizeof(double), size);
  double red_y = safe_double(data, 3 * sizeof(double), size);
  double green_x = safe_double(data, 4 * sizeof(double), size);
  double green_y = safe_double(data, 5 * sizeof(double), size);
  double blue_x = safe_double(data, 6 * sizeof(double), size);
  double blue_y = safe_double(data, 7 * sizeof(double), size);

  // Call png_set_cHRM
  png_set_cHRM(png_ptr, info_ptr, white_x, white_y, red_x, red_y, green_x, green_y, blue_x, blue_y);

#ifdef PNG_FLOATING_POINT_SUPPORTED
  if (size >= sizeof(double) * 11) {
    // Extract parameters for png_set_cHRM_XYZ
    double red_X = safe_double(data, 8 * sizeof(double), size);
    double red_Y = safe_double(data, 9 * sizeof(double), size);
    double red_Z = safe_double(data, 10 * sizeof(double), size);
    double green_X = safe_double(data, 11 * sizeof(double), size);
    double green_Y = safe_double(data, 12 * sizeof(double), size);
    double green_Z = safe_double(data, 13 * sizeof(double), size);
    double blue_X = safe_double(data, 14 * sizeof(double), size);
    double blue_Y = safe_double(data, 15 * sizeof(double), size);
    double blue_Z = safe_double(data, 16 * sizeof(double), size);

    png_set_cHRM_XYZ(png_ptr, info_ptr, red_X, red_Y, red_Z, green_X, green_Y, green_Z, blue_X, blue_Y, blue_Z);
  }
#endif

  if (size >= sizeof(png_fixed_point) * 9) {
    // Extract parameters for png_set_cHRM_XYZ_fixed
    png_fixed_point int_red_X = safe_fixed(data, 0 * sizeof(png_fixed_point), size);
    png_fixed_point int_red_Y = safe_fixed(data, 1 * sizeof(png_fixed_point), size);
    png_fixed_point int_red_Z = safe_fixed(data, 2 * sizeof(png_fixed_point), size);
    png_fixed_point int_green_X = safe_fixed(data, 3 * sizeof(png_fixed_point), size);
    png_fixed_point int_green_Y = safe_fixed(data, 4 * sizeof(png_fixed_point), size);
    png_fixed_point int_green_Z = safe_fixed(data, 5 * sizeof(png_fixed_point), size);
    png_fixed_point int_blue_X = safe_fixed(data, 6 * sizeof(png_fixed_point), size);
    png_fixed_point int_blue_Y = safe_fixed(data, 7 * sizeof(png_fixed_point), size);
    png_fixed_point int_blue_Z = safe_fixed(data, 8 * sizeof(png_fixed_point), size);

    png_set_cHRM_XYZ_fixed(png_ptr, info_ptr, int_red_X, int_red_Y, int_red_Z,
                           int_green_X, int_green_Y, int_green_Z,
                           int_blue_X, int_blue_Y, int_blue_Z);
  }


  return 0;
}