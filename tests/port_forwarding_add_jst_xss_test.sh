#!/bin/sh
if sed -n '602p' source/Styles/xb3/jst/port_forwarding_add.jst | grep -q "ENT_QUOTES"; then
    echo "PASS: HostName uses ENT_QUOTES"
else
    echo "FAIL: HostName does not use ENT_QUOTES"
    exit 1
fi
