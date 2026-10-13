#!/bin/sh
if sed -n '570,572p' source/Styles/xb6/jst/at_a_glance.jst | grep -q "ENT_QUOTES"; then
    echo "PASS: HostName uses ENT_QUOTES"
else
    echo "FAIL: HostName does not use ENT_QUOTES"
    exit 1
fi
