#!/bin/sh
if grep -q "JSON.parse" source/Styles/xb3/jst/connected_devices_computers.jst; then
    echo "PASS: JSON.parse used instead of eval()"
else
    echo "FAIL: JSON.parse not used"
    exit 1
fi
