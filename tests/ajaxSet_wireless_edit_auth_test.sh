#!/bin/sh
if grep -q "thisUser.*loginuser" source/Styles/xb3/code/actionHandler/ajaxSet_wireless_network_configuration_edit.php; then
    echo "PASS: thisUser validation present"
else
    echo "FAIL: thisUser validation missing"
    exit 1
fi
if grep -q "ERROR: Invalid SSID number" source/Styles/xb3/code/actionHandler/ajaxSet_wireless_network_configuration_edit.php; then
    echo "PASS: ssid_number validation present"
else
    echo "FAIL: ssid_number validation missing"
    exit 1
fi
