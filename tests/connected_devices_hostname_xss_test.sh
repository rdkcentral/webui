#!/bin/sh
if grep "X_CISCO_COM_HostName" source/Styles/xb3/code/connected_devices_computers.php | grep -q "ENT_QUOTES"; then
    echo "PASS: X_CISCO_COM_HostName uses ENT_QUOTES"
else
    echo "FAIL: X_CISCO_COM_HostName does not use ENT_QUOTES"
    exit 1
fi
