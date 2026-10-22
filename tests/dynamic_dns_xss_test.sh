#!/bin/sh
# Focused security regression test for XSS in dynamic_dns_edit.php
# Tests that ENT_QUOTES is used for username, password, and hostname fields

echo "Testing XSS protection in dynamic_dns_edit.php"

FAIL=0

# Test 1: Verify ENT_QUOTES is used for username field
if grep 'username.*htmlspecialchars.*ENT_QUOTES' source/Styles/xb3/code/dynamic_dns_edit.php > /dev/null 2>&1; then
    echo "PASS: username uses ENT_QUOTES"
else
    echo "FAIL: username does not use ENT_QUOTES"
    FAIL=1
fi

# Test 2: Verify ENT_QUOTES is used for password field
if grep 'password.*htmlspecialchars.*ENT_QUOTES' source/Styles/xb3/code/dynamic_dns_edit.php > /dev/null 2>&1; then
    echo "PASS: password uses ENT_QUOTES"
else
    echo "FAIL: password does not use ENT_QUOTES"
    FAIL=1
fi

# Test 3: Verify ENT_QUOTES is used for hostname field
if grep 'hostname.*htmlspecialchars.*ENT_QUOTES' source/Styles/xb3/code/dynamic_dns_edit.php > /dev/null 2>&1; then
    echo "PASS: hostname uses ENT_QUOTES"
else
    echo "FAIL: hostname does not use ENT_QUOTES"
    FAIL=1
fi

# Test 4: Verify UTF-8 charset is specified
if grep 'htmlspecialchars.*UTF-8' source/Styles/xb3/code/dynamic_dns_edit.php > /dev/null 2>&1; then
    echo "PASS: UTF-8 charset specified"
else
    echo "FAIL: UTF-8 charset not specified"
    FAIL=1
fi

# Test 5: Verify ENT_NOQUOTES is NOT used for username/password/hostname
if grep -E '(username|password|hostname).*htmlspecialchars.*ENT_NOQUOTES' source/Styles/xb3/code/dynamic_dns_edit.php > /dev/null 2>&1; then
    echo "FAIL: ENT_NOQUOTES used for sensitive field (should be ENT_QUOTES)"
    FAIL=1
else
    echo "PASS: ENT_NOQUOTES not used for sensitive fields"
fi

if [ $FAIL -eq 0 ]; then
    echo "PASS: All XSS protection tests passed"
else
    exit 1
fi
