#!/bin/sh
if grep -q "http_response_code(405)" source/Styles/xb3/jst/actionHandler/ajaxSet_wireless_network_configuration.jst; then
    echo "PASS: HTTP 405 response added"
else
    echo "FAIL: HTTP 405 response missing"
    exit 1
fi
