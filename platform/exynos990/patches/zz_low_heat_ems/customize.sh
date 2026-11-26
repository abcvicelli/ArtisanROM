# "Performance profile > Light" (SEC_FLOATING_FEATURE_SYSTEM_SUPPORT_LOW_HEAT_MODE)
# makes SDHMS acquire HyPer hint 900. The x1s vendor maps it to
# LOW_HEAT_MODE_HINT = CPUMaxFreq 90# + GPUMaxFreq 90#, which on this table only
# trims the big cluster from 2.73 to ~2.52 GHz and leaves the GPU untouched.
# Samsung's kernel already ships a power-saving EMS set for Exynos 990
# ("power-scenario": energy-aware placement that favours the A55 cluster and a
# slower energy_step ramp), but nothing in One UI 8.5 ever selects it. Add a
# sysfs resource for /sys/kernel/ems/emstune/req_mode and request mode 1 from
# hint 900, so Light really runs cooler. Standard mode is unchanged.
case "$TARGET_CODENAME" in
    x1s) ;;
    *) LOG "- Skipping: only validated on x1s"; return 0 ;;
esac

CONFIG="$WORK_DIR/vendor/etc/hyper/config_vendor.json"
if [ ! -f "$CONFIG" ] || ! grep -q '"LOW_HEAT_MODE_HINT"' "$CONFIG" || \
        ! grep -q '"KERNEL_CPU_MAX_CORE_NOTIFY"' "$CONFIG"; then
    LOGW "- $CONFIG has no LOW_HEAT_MODE_HINT, skipping"
    return 0
fi
if grep -q '"EMSTUNE_LOW_HEAT"' "$CONFIG"; then
    LOG "- EMSTUNE_LOW_HEAT already present"
    return 0
fi

LOG "- Adding EMS power-scenario to LOW_HEAT_MODE_HINT in /vendor/etc/hyper/config_vendor.json"
python3 - "$CONFIG" <<'PYEOF' || ABORT "Failed to patch $CONFIG"
import json, re, sys
path = sys.argv[1]
src = open(path).read()
i = src.find('"Name": "KERNEL_CPU_MAX_CORE_NOTIFY"')
j = src.find('\n    },', i)
if i < 0 or j < 0:
    sys.exit("resource anchor not found")
res = '''
    },
    {
      "Name": "EMSTUNE_LOW_HEAT",
      "ID" : "0x60030000",
      "Handler" : "sysfs",
      "BoostPath" : "/sys/kernel/ems/emstune/req_mode",
      "Priority" : "high",
      "DefaultValue": "0",
      "Values": [
        "1","0"
      ]'''
out = src[:j] + res + src[j:]
k = out.find('"Hint": "LOW_HEAT_MODE_HINT"')
end = out.find(']', k)
tail = out.rfind('}', k, end)
if k < 0 or end < 0 or tail < 0:
    sys.exit("hint anchor not found")
add = ''',
        {
            "Resource" : "EMSTUNE_LOW_HEAT",
            "Value" : "1"
        }'''
out = out[:tail + 1] + add + out[tail + 1:]
try:
    json.loads(out)
except ValueError:
    json.loads(re.sub(r",\s*([\]}])", r"\1", out))
open(path, 'w').write(out)
PYEOF
grep -q '"EMSTUNE_LOW_HEAT"' "$CONFIG" || ABORT "EMSTUNE_LOW_HEAT not added to $CONFIG"
