# Local builds only. Preloads updated copies of Samsung apps (Smart Switch,
# Samsung account, Galaxy Store...) so a clean install can run Smart Switch
# right away. The APKs are proprietary and are NOT part of this repository:
# they are read from $LOCAL_PRELOAD_DIR (default: ../../preload_apks; runs as a mod, after debloat.sh removes /system/preload), one
# <package>.apk per app. /system/preload apps are installed on first boot
# as regular updates; one that cannot be installed is simply skipped.
PRELOAD_SRC="${LOCAL_PRELOAD_DIR:-$SRC_DIR/../../preload_apks}"
if ! ls "$PRELOAD_SRC"/*.apk > /dev/null 2>&1; then
    LOG "- No local preload APKs in $PRELOAD_SRC; skipping"
    return 0
fi

VPL_LIST="$WORK_DIR/system/system/etc/vpl_apks_count_list.txt"
for APK in "$PRELOAD_SRC"/*.apk; do
    PKG="$(basename "$APK" .apk)"
    DIR="system/preload/$PKG"
    DEST="$DIR/$PKG-mesa==/base.apk"
    LOG "- Preloading $PKG"
    mkdir -p "$WORK_DIR/system/$DIR/$PKG-mesa=="
    cp -f "$APK" "$WORK_DIR/system/$DEST"
    SET_METADATA "system" "$DIR" 0 0 755 "u:object_r:system_file:s0"
    SET_METADATA "system" "$DIR/$PKG-mesa==" 0 0 755 "u:object_r:system_file:s0"
    SET_METADATA "system" "$DEST" 0 0 644 "u:object_r:system_file:s0"
    if [ -f "$VPL_LIST" ] && ! grep -qF "$DEST" "$VPL_LIST"; then
        echo "$DEST" >> "$VPL_LIST"
    fi
done
unset PRELOAD_SRC VPL_LIST APK PKG DIR DEST
