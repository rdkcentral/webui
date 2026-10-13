#!/bin/sh
if grep -q "ERROR: Invalid SSID number" source/Styles/xb3/code/actionHandler/ajaxSet_wireless_network_configuration.php; then
    echo "PASS: ssid_number validation present"
else
    echo "FAIL: ssid_number validation missing"
    exit 1
fi
