
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := keyutils
LOCAL_DESCRIPTION := keyutils module

LOCAL_AUTOTOOLS_MAKE_BUILD_ARGS := all CC=$(TARGET_CROSS)gcc
LOCAL_AUTOTOOLS_MAKE_INSTALL_ARGS := lib=lib

define LOCAL_AUTOTOOLS_CMD_CONFIGURE
	cp -r $(PRIVATE_PATH)/*  $(call module-get-build-dir,keyutils)/obj
	rm -f $(call module-get-build-dir,keyutils)/obj/atom.mk
endef

include $(BUILD_AUTOTOOLS)

