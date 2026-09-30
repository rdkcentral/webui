#!/bin/sh
if grep -q "ENT_QUOTES" source/Styles/xb3/code/dynamic_dns_edit.php; then
    echo "PASS: ENT_QUOTES used for dynamic DNS fields"
else
    echo "FAIL: ENT_QUOTES not used"
    exit 1
fi
