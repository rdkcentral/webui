#!/bin/sh
# Focused security regression test for XSS in connected_devices_computers.php
# Tests that HostName and Comments are encoded with ENT_QUOTES

echo "Testing XSS protection in connected_devices_computers.php"

FAIL=0

# Test 1: Verify HostName encoding with ENT_QUOTES and UTF-8
if grep 'HostName.*htmlspecialchars.*ENT_QUOTES.*UTF-8' source/Styles/xb3/code/connected_devices_computers.php > /dev/null 2>&1; then
    echo "PASS: HostName uses ENT_QUOTES with UTF-8"
else
    echo "FAIL: HostName does not use ENT_QUOTES with UTF-8"
    FAIL=1
fi

# Test 2: Verify Comments encoding with ENT_QUOTES and UTF-8
if grep 'Comments.*htmlspecialchars.*ENT_QUOTES.*UTF-8' source/Styles/xb3/code/connected_devices_computers.php > /dev/null 2>&1; then
    echo "PASS: Comments uses ENT_QUOTES with UTF-8"
else
    echo "FAIL: Comments does not use ENT_QUOTES with UTF-8"
    FAIL=1
fi

# Test 3: Verify ENT_NOQUOTES is NOT used for HostName
if grep 'HostName.*htmlspecialchars.*ENT_NOQUOTES' source/Styles/xb3/code/connected_devices_computers.php > /dev/null 2>&1; then
    echo "FAIL: ENT_NOQUOTES used for HostName (should be ENT_QUOTES)"
    FAIL=1
else
    echo "PASS: ENT_NOQUOTES not used for HostName"
fi

# Test 4: Verify ENT_NOQUOTES is NOT used for Comments
if grep 'Comments.*htmlspecialchars.*ENT_NOQUOTES' source/Styles/xb3/code/connected_devices_computers.php > /dev/null 2>&1; then
    echo "FAIL: ENT_NOQUOTES used for Comments (should be ENT_QUOTES)"
    FAIL=1
else
    echo "PASS: ENT_NOQUOTES not used for Comments"
fi

if [ $FAIL -eq 0 ]; then
    echo "PASS: All XSS protection tests passed"
else
    exit 1
fi
