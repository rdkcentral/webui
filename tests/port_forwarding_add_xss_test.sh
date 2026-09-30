#!/bin/sh
if grep "HostName" source/Styles/xb3/code/port_forwarding_add.php | grep -q "ENT_QUOTES"; then
    echo "PASS: HostName uses ENT_QUOTES"
else
    echo "FAIL: HostName does not use ENT_QUOTES"
    exit 1
fi
