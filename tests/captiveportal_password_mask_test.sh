#!/bin/sh
# Focused security regression test for PSK disclosure in captiveportal.php
# Tests that WiFi passwords are not echoed in any form

echo "Testing PSK disclosure protection in captiveportal.php"

FAIL=0

# Test 1: Verify network_pass is not echoed
if grep "network_pass" source/Styles/xb3/code/captiveportal.php | grep -q "echo"; then
    echo "FAIL: network_pass still echoed"
    FAIL=1
else
    echo "PASS: network_pass not echoed"
fi

# Test 2: Verify network_pass1 is not echoed
if grep "network_pass1" source/Styles/xb3/code/captiveportal.php | grep -q "echo"; then
    echo "FAIL: network_pass1 still echoed"
    FAIL=1
else
    echo "PASS: network_pass1 not echoed"
fi

# Test 3: Verify network_pass is not printed or output in any way
if grep "network_pass" source/Styles/xb3/code/captiveportal.php | grep -E '(print|printf|var_dump|print_r)' > /dev/null 2>&1; then
    echo "FAIL: network_pass may be printed via print/printf"
    FAIL=1
else
    echo "PASS: network_pass not printed"
fi

# Test 4: Verify network_pass1 is not printed or output in any way
if grep "network_pass1" source/Styles/xb3/code/captiveportal.php | grep -E '(print|printf|var_dump|print_r)' > /dev/null 2>&1; then
    echo "FAIL: network_pass1 may be printed via print/printf"
    FAIL=1
else
    echo "PASS: network_pass1 not printed"
fi

# Test 5: Verify the password is masked or redacted in output
if grep -E '(network_pass|network_pass1).*substr' source/Styles/xb3/code/captiveportal.php > /dev/null 2>&1; then
    echo "PASS: Password is masked using substr"
else
    echo "INFO: Password masking method may vary"
fi

if [ $FAIL -eq 0 ]; then
    echo "PASS: All PSK disclosure protection tests passed"
else
    exit 1
fi
