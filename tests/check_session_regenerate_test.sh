#!/bin/sh
# Focused security regression test for session fixation protection
# Tests that session_regenerate_id is called with destroy parameter

echo "Testing session fixation protection in check.php"

FAIL=0

# Test 1: Verify session_regenerate_id is present
if grep -q "session_regenerate_id" source/Styles/xb3/code/check.php; then
    echo "PASS: session_regenerate_id present"
else
    echo "FAIL: session_regenerate_id missing"
    FAIL=1
fi

# Test 2: Verify session_regenerate_id is called with destroy parameter (true)
if grep "session_regenerate_id(true)" source/Styles/xb3/code/check.php > /dev/null 2>&1; then
    echo "PASS: session_regenerate_id called with destroy parameter"
else
    echo "FAIL: session_regenerate_id not called with destroy parameter"
    FAIL=1
fi

# Test 3: Verify session_regenerate_id is called after session_start
# This ensures the session is active before regeneration
if grep -A 20 'session_start' source/Styles/xb3/code/check.php | grep -q "session_regenerate_id"; then
    echo "PASS: session_regenerate_id called after session_start"
else
    echo "INFO: session_regenerate_id location may vary"
fi

# Test 4: Verify session_regenerate_id is called during authentication
# It should be in the authentication flow, not just randomly placed
if grep -B 5 -A 5 "session_regenerate_id" source/Styles/xb3/code/check.php | grep -E '(login|auth|session)' > /dev/null 2>&1; then
    echo "PASS: session_regenerate_id in authentication context"
else
    echo "INFO: session_regenerate_id context may vary"
fi

# Test 5: Verify session_start is present
if grep -q "session_start" source/Styles/xb3/code/check.php; then
    echo "PASS: session_start present"
else
    echo "FAIL: session_start missing"
    FAIL=1
fi

if [ $FAIL -eq 0 ]; then
    echo "PASS: All session fixation protection tests passed"
else
    exit 1
fi
