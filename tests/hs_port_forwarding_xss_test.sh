#!/bin/sh
if grep "Description.*ENT_QUOTES" source/Styles/xb3/code/hs_port_forwarding.php; then
    echo "PASS: Description uses ENT_QUOTES"
else
    echo "FAIL: Description does not use ENT_QUOTES"
    exit 1
fi
