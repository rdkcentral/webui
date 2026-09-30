#!/bin/sh
if grep "HostName" source/Styles/xb3/code/connected_devices_computers.php | grep -q "ENT_QUOTES"; then
    echo "PASS: HostName uses ENT_QUOTES"
else
    echo "FAIL: HostName does not use ENT_QUOTES"
    exit 1
fi
if grep "Comments" source/Styles/xb3/code/connected_devices_computers.php | grep -q "ENT_QUOTES"; then
    echo "PASS: Comments uses ENT_QUOTES"
else
    echo "FAIL: Comments does not use ENT_QUOTES"
    exit 1
fi
