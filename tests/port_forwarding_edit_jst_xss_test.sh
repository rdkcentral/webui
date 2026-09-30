#!/bin/sh
if sed -n '71p' source/Styles/xb3/jst/port_forwarding_edit.jst | grep -q "ENT_QUOTES"; then
    echo "PASS: service_name uses ENT_QUOTES"
else
    echo "FAIL: service_name does not use ENT_QUOTES"
    exit 1
fi
