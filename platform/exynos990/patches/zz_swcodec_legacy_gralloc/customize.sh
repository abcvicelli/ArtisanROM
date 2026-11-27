# The Exynos 990 vendor only ships android.hardware.graphics.mapper@2.1
# (allocator 2.0). libui's GraphicBufferMapper falls back from Gralloc5/4 to
# Gralloc3/2, but recent Google builds of the media.swcodec APEX skip that
# fallback when android_get_device_api_level() > 35, so after Play updates the
# module (e.g. 373041580) the media.swcodec service aborts with "gralloc-mapper
# is missing" and every c2.android.* software codec is gone. LineageOS builds
# libui with legacy_gralloc=true for the same reason ("We don't have gralloc 4
# or higher"); we cannot rebuild Google's prebuilt, so keep the bundled module
# (361521100, which still falls back) instead.
#
# Re-sign it with our own keys and give the container the AOSP package name
# (com.android.media.swcodec), the same thing Samsung does for com.android.wifi,
# .bt and .uwb in this firmware: Play then no longer treats it as the Google
# module and stops staging updates for it, while every other mainline module
# keeps updating. A Play build already sitting in /data/apex/active is
# rejected by apexd at boot because its key no longer matches.
APEX="$WORK_DIR/system/system/apex/com.google.android.media.swcodec_compressed.apex"

if [ ! -f "$APEX" ]; then
    LOG "- No Google media.swcodec APEX, skipping"
    return 0
fi

if [ -f "$WORK_DIR/vendor/lib64/hw/android.hardware.graphics.mapper@4.0-impl.so" ] || \
        compgen -G "$WORK_DIR/vendor/lib64/hw/mapper.*.so" > /dev/null; then
    LOG "- Vendor provides gralloc 4 or newer, skipping"
    return 0
fi

if ! unzip -p "$APEX" AndroidManifest.xml | grep -aq "c.o.m...g.o.o.g.l.e...a.n.d.r.o.i.d...m.e.d.i.a...s.w.c.o.d.e.c\|com\.google\.android\.media\.swcodec"; then
    LOG "- media.swcodec APEX already re-signed"
    return 0
fi

CERT_PREFIX="aosp"
if $ROM_IS_OFFICIAL; then
    CERT_PREFIX="artisanrom"
fi

LOG "- Re-signing /system/apex/$(basename "$APEX") as com.android.media.swcodec"
EVAL "python3 -I \"$MODPATH/resign_capex.py\" \
    --input \"$APEX\" --output \"$APEX.resigned\" \
    --avbtool \"$(command -v avbtool)\" --signapk \"$(command -v signapk)\" \
    --cert \"$SRC_DIR/security/${CERT_PREFIX}_platform.x509.pem\" \
    --key \"$SRC_DIR/security/${CERT_PREFIX}_platform.pk8\" \
    --avb-key \"$SRC_DIR/security/avb/testkey_rsa4096.pem\" \
    --key-name com.android.media.swcodec \
    --rename-package com.google.android.media.swcodec=com.android.media.swcodec" \
    || ABORT "Failed to re-sign $APEX"
mv -f "$APEX.resigned" "$APEX"

unset APEX CERT_PREFIX
