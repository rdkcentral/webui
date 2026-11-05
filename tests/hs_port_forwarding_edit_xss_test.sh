#!/bin/sh
# Focused security regression test for XSS in hs_port_forwarding_edit.php
# Tests that service_name is encoded with ENT_QUOTES

echo "Testing XSS protection in hs_port_forwarding_edit.php"

FAIL=0

# Test 1: Verify service_name encoding with ENT_QUOTES and UTF-8
if grep 'service_name.*htmlspecialchars.*ENT_QUOTES.*UTF-8' source/Styles/xb3/code/hs_port_forwarding_edit.php > /dev/null 2>&1; then
    echo "PASS: service_name uses ENT_QUOTES with UTF-8"
else
    echo "FAIL: service_name does not use ENT_QUOTES with UTF-8"
    FAIL=1
fi

# Test 2: Verify ENT_NOQUOTES is NOT used for service_name
if grep 'service_name.*htmlspecialchars.*ENT_NOQUOTES' source/Styles/xb3/code/hs_port_forwarding_edit.php > /dev/null 2>&1; then
    echo "FAIL: ENT_NOQUOTES used for service_name (should be ENT_QUOTES)"
    FAIL=1
else
    echo "PASS: ENT_NOQUOTES not used for service_name"
fi

# Test 3: Verify the encoding is applied to the PortMapping.Description value
if grep 'PortMapping.*Description.*htmlspecialchars' source/Styles/xb3/code/hs_port_forwarding_edit.php > /dev/null 2>&1; then
    echo "PASS: PortMapping.Description is encoded"
else
    echo "INFO: Encoding may be applied after value extraction"
fi

# Test 4: Verify the encoded value is assigned to service_name variable
if grep 'service_name.*=.*htmlspecialchars' source/Styles/xb3/code/hs_port_forwarding_edit.php > /dev/null 2>&1; then
    echo "PASS: Encoded value assigned to service_name"
else
    echo "FAIL: Encoded value not assigned to service_name"
    FAIL=1
fi

if [ $FAIL -eq 0 ]; then
    echo "PASS: All XSS protection tests passed"
else
    exit 1
fi
