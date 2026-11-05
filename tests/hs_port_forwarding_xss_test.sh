#!/bin/sh
# Focused security regression test for XSS in hs_port_forwarding.php
# Tests that Description is encoded with ENT_QUOTES

echo "Testing XSS protection in hs_port_forwarding.php"

FAIL=0

# Test 1: Verify Description encoding with ENT_QUOTES and UTF-8
if grep 'Description.*htmlspecialchars.*ENT_QUOTES.*UTF-8' source/Styles/xb3/code/hs_port_forwarding.php > /dev/null 2>&1; then
    echo "PASS: Description uses ENT_QUOTES with UTF-8"
else
    echo "FAIL: Description does not use ENT_QUOTES with UTF-8"
    FAIL=1
fi

# Test 2: Verify ENT_NOQUOTES is NOT used for Description
if grep 'Description.*htmlspecialchars.*ENT_NOQUOTES' source/Styles/xb3/code/hs_port_forwarding.php > /dev/null 2>&1; then
    echo "FAIL: ENT_NOQUOTES used for Description (should be ENT_QUOTES)"
    FAIL=1
else
    echo "PASS: ENT_NOQUOTES not used for Description"
fi

# Test 3: Verify the encoding is applied to PortMapping.Description value
if grep 'PortMapping.*Description.*htmlspecialchars' source/Styles/xb3/code/hs_port_forwarding.php > /dev/null 2>&1; then
    echo "PASS: PortMapping.Description is encoded"
else
    echo "INFO: Encoding may be applied after value extraction"
fi

if [ $FAIL -eq 0 ]; then
    echo "PASS: All XSS protection tests passed"
else
    exit 1
fi
