# Android 16's PackageManager protects /data/system/users/<id>/package-restrictions.xml
# with fs-verity (FS_IOC_ENABLE_VERITY, 0x6685). Samsung labels /data/system/users
# as the vendor type users_system_data_file, and newer vendors grant that ioctl:
#   (allowx system_server_34_0 users_system_data_file (ioctl file (0x6685)))
# The Android 11 Exynos 990 vendor policy predates it, so every write fails with
# "Failed to verity-protect package restrictions ... Permission denied".
VENDOR_POLICY="$WORK_DIR/vendor/etc/selinux/vendor_sepolicy.cil"
VERS_FILE="$WORK_DIR/vendor/etc/selinux/plat_sepolicy_vers.txt"

if [ ! -f "$VENDOR_POLICY" ] || [ ! -f "$VERS_FILE" ]; then
    LOGW "- Vendor SELinux policy not found, skipping"
    return 0
fi

VERS="$(tr -d '[:space:]' < "$VERS_FILE")"
SYSTEM_SERVER="system_server_${VERS//./_}"
MAPPING="$WORK_DIR/system/system/etc/selinux/mapping/$VERS.cil"

if ! grep -q -F '(type users_system_data_file)' "$VENDOR_POLICY" || \
        [ ! -f "$MAPPING" ] || \
        ! grep -q -F "(typeattributeset $SYSTEM_SERVER (system_server))" "$MAPPING"; then
    LOGW "- users_system_data_file or $SYSTEM_SERVER not available, skipping"
    return 0
fi

if ! grep -q -F "(allowx $SYSTEM_SERVER users_system_data_file (ioctl file (0x6685)))" "$VENDOR_POLICY"; then
    LOG "- Allowing fs-verity on users_system_data_file for system_server"
    printf '%s\n' "(allowx $SYSTEM_SERVER users_system_data_file (ioctl file (0x6685)))" >> "$VENDOR_POLICY"
fi
