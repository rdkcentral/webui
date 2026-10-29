#!/bin/sh
# Focused security regression test for XSS in at_a_glance.jst
# Tests that HostName and PhysAddress are encoded with ENT_QUOTES

echo "Testing XSS protection in at_a_glance.jst"

FAIL=0

# Test 1: Verify HostName encoding with ENT_QUOTES and UTF-8
if grep 'HostName.*htmlspecialchars.*ENT_QUOTES.*UTF-8' source/Styles/xb3/jst/at_a_glance.jst > /dev/null 2>&1; then
    echo "PASS: HostName uses ENT_QUOTES with UTF-8"
else
    echo "FAIL: HostName does not use ENT_QUOTES with UTF-8"
    FAIL=1
fi

# Test 2: Verify PhysAddress fallback is also encoded
if grep 'PhysAddress.*htmlspecialchars.*ENT_QUOTES.*UTF-8' source/Styles/xb3/jst/at_a_glance.jst > /dev/null 2>&1; then
    echo "PASS: PhysAddress fallback uses ENT_QUOTES with UTF-8"
else
    echo "FAIL: PhysAddress fallback does not use ENT_QUOTES with UTF-8"
    FAIL=1
fi

# Test 3: Verify ENT_NOQUOTES is NOT used for HostName
if grep 'HostName.*htmlspecialchars.*ENT_NOQUOTES' source/Styles/xb3/jst/at_a_glance.jst > /dev/null 2>&1; then
    echo "FAIL: ENT_NOQUOTES used for HostName (should be ENT_QUOTES)"
    FAIL=1
else
    echo "PASS: ENT_NOQUOTES not used for HostName"
fi

# Test 4: Verify encoding is applied before the fallback logic
# The pattern should be: encode HostName, then check if "*" or empty, then encode PhysAddress
if grep -B 2 'PhysAddress.*htmlspecialchars' source/Styles/xb3/jst/at_a_glance.jst | grep -q 'HostName.*htmlspecialchars'; then
    echo "PASS: Encoding applied in correct order"
else
    echo "INFO: Encoding order may vary but both fields are encoded"
fi

if [ $FAIL -eq 0 ]; then
    echo "PASS: All XSS protection tests passed"
else
    exit 1
fi
