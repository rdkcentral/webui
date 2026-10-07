#!/bin/sh
if sed -n '270p' source/Styles/xb3/code/managed_devices_add_computer_allowed.php | grep -q "ENT_QUOTES"; then
    echo "PASS: HostName uses ENT_QUOTES"
else
    echo "FAIL: HostName does not use ENT_QUOTES"
    exit 1
fi
