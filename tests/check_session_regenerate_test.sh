#!/bin/sh
if grep -q "session_regenerate_id" source/Styles/xb3/code/check.php; then
    echo "PASS: session_regenerate_id present"
else
    echo "FAIL: session_regenerate_id missing"
    exit 1
fi
