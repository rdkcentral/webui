#!/bin/sh
if grep -q "JSON.parse" source/Styles/xb3/code/connected_devices_computers.php; then
    echo "PASS: JSON.parse used instead of eval()"
else
    echo "FAIL: JSON.parse not used"
    exit 1
fi
