LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

include $(LOCAL_PATH)/Common.mk

LOCAL_SRC_FILES := $(SRC_C)

# -pedantic yields a lot of warnings from the NDK includes
LOCAL_CFLAGS := $(filter-out -pedantic,$(CFLAGS))

# Separate, since changing it on its own will break the Android app
LOCAL_MODULE := bmx6

LOCAL_FORCE_STATIC_EXECUTABLE := true

include $(BUILD_EXECUTABLE)
