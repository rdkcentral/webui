#!/bin/sh
if grep -q "if (!isset(\$_SESSION\['loginStatus'\])" source/Styles/xb3/code/actionHandler/ajaxSet_self_heal_restart.php; then
    echo "PASS: session check present"
else
    echo "FAIL: session check missing"
    exit 1
fi
if grep -q "http_response_code(403)" source/Styles/xb3/code/actionHandler/ajaxSet_self_heal_restart.php; then
    echo "PASS: 403 response on auth failure"
else
    echo "FAIL: 403 response missing"
    exit 1
fi
