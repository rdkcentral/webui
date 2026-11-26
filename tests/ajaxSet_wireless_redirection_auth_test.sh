#!/bin/sh
if grep -q "session_start" source/Styles/xb3/jst/actionHandler/ajaxSet_wireless_network_configuration_redirection.jst; then
    echo "PASS: session_start present"
else
    echo "FAIL: session_start missing"
    exit 1
fi
