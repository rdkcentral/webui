#!/bin/sh
# Focused security regression test for XSS in at_a_glance variants
# Tests that ENT_QUOTES is used for HostName in all variants

echo "Testing XSS protection in at_a_glance variants"

FAIL=0

# Test 1: Verify xb3 PHP variant
if grep "HostName" source/Styles/xb3/code/at_a_glance.php | grep -q "ENT_QUOTES"; then
    echo "PASS: HostName uses ENT_QUOTES in xb3 PHP"
else
    echo "FAIL: HostName does not use ENT_QUOTES in xb3 PHP"
    FAIL=1
fi

# Test 2: Verify xb6 PHP variant
if grep "HostName" source/Styles/xb6/code/at_a_glance.php | grep -q "ENT_QUOTES"; then
    echo "PASS: HostName uses ENT_QUOTES in xb6 PHP"
else
    echo "FAIL: HostName does not use ENT_QUOTES in xb6 PHP"
    FAIL=1
fi

# Test 3: Verify xb3 JST variant
if grep "HostName" source/Styles/xb3/jst/at_a_glance.jst | grep -q "ENT_QUOTES"; then
    echo "PASS: HostName uses ENT_QUOTES in xb3 JST"
else
    echo "FAIL: HostName does not use ENT_QUOTES in xb3 JST"
    FAIL=1
fi

# Test 4: Verify xb6 JST variant
if grep "HostName" source/Styles/xb6/jst/at_a_glance.jst | grep -q "ENT_QUOTES"; then
    echo "PASS: HostName uses ENT_QUOTES in xb6 JST"
else
    echo "FAIL: HostName does not use ENT_QUOTES in xb6 JST"
    FAIL=1
fi

if [ $FAIL -eq 0 ]; then
    echo "PASS: All XSS protection tests passed"
else
    exit 1
fi
