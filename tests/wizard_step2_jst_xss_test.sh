#!/bin/sh
if grep -q "json_encode.*network_name" source/Styles/xb3/jst/wizard_step2.jst; then
    echo "PASS: json_encode used for network_name"
else
    echo "FAIL: json_encode not used for network_name"
    exit 1
fi
