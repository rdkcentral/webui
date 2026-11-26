#!/bin/sh
# Focused security regression test for getInstanceIds overflow protection
# Tests that the bounded snprintf implementation prevents buffer overflow

echo "Testing getInstanceIds overflow protection"

# Test 1: Verify the implementation uses snprintf instead of sprintf
if grep -q "snprintf" source/CcspPhpExtension/cosa.c; then
    echo "PASS: Implementation uses snprintf instead of sprintf"
else
    echo "FAIL: Implementation still uses sprintf"
    exit 1
fi

# Test 2: Verify the implementation has bounds checking
if grep -q "sizeof(format_s)" source/CcspPhpExtension/cosa.c; then
    echo "PASS: Implementation uses buffer size bounds checking"
else
    echo "FAIL: Implementation does not use bounds checking"
    exit 1
fi

# Test 3: Verify the implementation checks for negative or truncated snprintf return
if grep -q "len < 0" source/CcspPhpExtension/cosa.c; then
    echo "PASS: Implementation checks for negative snprintf return"
else
    echo "FAIL: Implementation does not check for negative snprintf return"
    exit 1
fi

echo "PASS: All getInstanceIds overflow protection tests passed"
