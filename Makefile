hide := @
ECHO := echo

SYS_PATH := ../../buildroot/output/rockchip_puma/host/arm-buildroot-linux-gnueabihf/sysroot
OUT_PATH := ../../buildroot/output/rockchip_puma/target
STAGOUT_PATH := ../../buildroot/output/rockchip_puma/staging
INC_FILES := -I $(SYS_PATH)/usr/include \
             -I $(SYS_PATH)/usr/include/dbus-1.0 \
             -I $(SYS_PATH)/usr/lib/dbus-1.0/include \
             -I $(SYS_PATH)/usr/include/glib-2.0 \
             -I $(SYS_PATH)/usr/lib/glib-2.0/include \
             -I $(SYS_PATH)/usr/include/libdrm \
             -I $(OUT_PATH)/usr/include
LIB_FILES := -L $(OUT_PATH)/usr/lib

LD_FLAGS := -lpthread -lm -ldbus-1 -ldbus-glib-1 -lglib-2.0 -lgio-2.0 -lgobject-2.0 -lreadline -ljson-c -lgdbus
SRC_FILES := agent.c dbus_helpers.c netctl.c main.c db_monitor.c dbus.c manage.c network_func.c

BIN_FILE := netserver

out:
	$(hide)$(ECHO) "Build ..."
	./../../buildroot/output/rockchip_puma/host/usr/bin/arm-buildroot-linux-gnueabihf-gcc $(SRC_FILES) $(INC_FILES) $(LIB_FILES) $(LD_FLAGS) -o $(BIN_FILE)
	cp dbusconfig/netserver.conf $(STAGOUT_PATH)/etc/dbus-1/system.d/
	cp netserver $(STAGOUT_PATH)/usr/bin/
	$(hide)$(ECHO) "Build Done ..."
