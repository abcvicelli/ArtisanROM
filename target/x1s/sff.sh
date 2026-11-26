# Copyright (c) 2025 Salvo Giangreco
# SPDX-License-Identifier: GPL-3.0-or-later

# SEC Floating Feature configuration file for Galaxy S20 (Exynos) (x1s)

# Enable AOD live clock
SEC_FLOATING_FEATURE_FRAMEWORK_CONFIG_AOD_ITEM=activeclock=7,aodversion=7,clocktransition,coverboldfont

# Set default HFR Refresh Rate
SEC_FLOATING_FEATURE_LCD_CONFIG_HFR_DEFAULT_REFRESH_RATE=120

# Enable seamless refresh rate feature
SEC_FLOATING_FEATURE_LCD_CONFIG_HFR_MODE=2

# Enable extra brightness feature
SEC_FLOATING_FEATURE_LCD_SUPPORT_EXTRA_BRIGHTNESS=TRUE

# Stock x1s features that One UI 8.5 still reads but the generic merge drops
# (listed as DEPRECATED or missing from the stock x1s table):
# - "Performance profile > Light": SDHMS acquires HyPer hint 900, which the
#   x1s vendor HAL maps to LOW_HEAT_MODE_HINT (CPU/GPU max 90%).
SEC_FLOATING_FEATURE_SYSTEM_SUPPORT_LOW_HEAT_MODE=TRUE
# - Wi-Fi power saving mode: semwifi-service sends SET_ADPS, which bcmdhd
#   (BCM4375, WLADPS_PRIVATE_CMD) implements.
SEC_FLOATING_FEATURE_WIFI_SUPPORT_ADPS=TRUE
# - eSIM: the x1s has a working eUICC (slot 1) and the eSIM apps are present.
SEC_FLOATING_FEATURE_COMMON_SUPPORT_EMBEDDED_SIM=TRUE
# - Wireless PowerShare while charging from a 5 V adapter (stock x1s value).
SEC_FLOATING_FEATURE_BATTERY_SUPPORT_WIRELESS_TX_5V_TA=TRUE
