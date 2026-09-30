#!/bin/sh
if grep "service_name" source/Styles/xb3/code/hs_port_forwarding_edit.php | grep -q "ENT_QUOTES"; then
    echo "PASS: service_name uses ENT_QUOTES"
else
    echo "FAIL: service_name does not use ENT_QUOTES"
    exit 1
fi
