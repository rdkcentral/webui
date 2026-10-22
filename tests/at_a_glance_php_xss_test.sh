#!/bin/sh
if sed -n '409,411p' source/Styles/xb6/code/at_a_glance.php | grep -q "ENT_QUOTES"; then
    echo "PASS: HostName uses ENT_QUOTES"
else
    echo "FAIL: HostName does not use ENT_QUOTES"
    exit 1
fi
