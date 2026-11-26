#!/bin/sh
if grep -q "if (!isset(\$_SESSION\['loginStatus'\])" source/Styles/xb3/code/includes/actionHandlerUtility.php; then
    echo "PASS: session check present"
else
    echo "FAIL: session check missing"
    exit 1
fi
if grep -q "http_response_code(403)" source/Styles/xb3/code/includes/actionHandlerUtility.php; then
    echo "PASS: 403 response on auth failure"
else
    echo "FAIL: 403 response missing"
    exit 1
fi
session_count=$(grep -c "session_start()" source/Styles/xb3/code/includes/actionHandlerUtility.php)
if [ "$session_count" -eq 1 ]; then
    echo "PASS: single session_start call"
else
    echo "FAIL: duplicate session_start calls ($session_count)"
    exit 1
fi
