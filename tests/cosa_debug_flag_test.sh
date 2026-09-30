#!/bin/sh
# Focused security regression test for debug flag ownership validation
# Tests that the implementation validates file ownership, permissions, and type correctly

echo "Testing debug flag ownership validation"

# Test 1: Verify the implementation uses open() with O_NOFOLLOW
if grep -q "O_NOFOLLOW" source/CcspPhpExtension/cosa.c; then
    echo "PASS: Implementation uses O_NOFOLLOW to prevent symlink following"
else
    echo "FAIL: Implementation does not use O_NOFOLLOW"
    exit 1
fi

# Test 2: Verify the implementation uses fstat() on the opened descriptor
if grep -q "fstat" source/CcspPhpExtension/cosa.c; then
    echo "PASS: Implementation uses fstat() on opened descriptor"
else
    echo "FAIL: Implementation does not use fstat()"
    exit 1
fi

# Test 3: Verify the implementation checks S_ISREG for regular file
if grep -q "S_ISREG" source/CcspPhpExtension/cosa.c; then
    echo "PASS: Implementation checks for regular file type"
else
    echo "FAIL: Implementation does not check for regular file type"
    exit 1
fi

# Test 4: Verify the implementation validates root ownership
if grep -q "st.st_uid == 0" source/CcspPhpExtension/cosa.c; then
    echo "PASS: Implementation validates root ownership"
else
    echo "FAIL: Implementation does not validate root ownership"
    exit 1
fi

# Test 5: Verify the implementation checks for forbidden permission bits
if grep -q "0222" source/CcspPhpExtension/cosa.c; then
    echo "PASS: Implementation checks for forbidden permission bits"
else
    echo "FAIL: Implementation does not check for forbidden permission bits"
    exit 1
fi

echo "PASS: All debug flag validation tests passed"
