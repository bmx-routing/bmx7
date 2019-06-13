# Older platforms don't have fdprintf and vfdprintf
APP_PLATFORM := android-8

# GCC 4.8/4.9 build arm binaries that crashed due to memory alignment issues.
# Clang build binaries that ran fine.
NDK_TOOLCHAIN_VERSION := clang
