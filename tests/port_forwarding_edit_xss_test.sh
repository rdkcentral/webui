#!/bin/sh
# Focused security regression test for XSS in port_forwarding_edit.php
# Tests that ENT_QUOTES is used for service_name encoding

echo "Testing XSS protection in port_forwarding_edit.php"

# Test 1: Verify ENT_QUOTES is used for service_name in PHP file
if grep -q "service_name.*ENT_QUOTES" source/Styles/xb3/code/port_forwarding_edit.php; then
    echo "PASS: service_name uses ENT_QUOTES in PHP file"
else
    echo "FAIL: service_name does not use ENT_QUOTES in PHP file"
    exit 1
fi

# Test 2: Verify ENT_QUOTES is used for service_name in JST file
if grep -q "service_name.*ENT_QUOTES" source/Styles/xb3/jst/port_forwarding_edit.jst; then
    echo "PASS: service_name uses ENT_QUOTES in JST file"
else
    echo "FAIL: service_name does not use ENT_QUOTES in JST file"
    exit 1
fi

echo "PASS: All XSS protection tests passed"
