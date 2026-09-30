#!/bin/sh
if grep -q "\$_GET\['configInfo'\]" source/Styles/xb6/jst/actionHandler/ajaxSet_wireless_network_configuration.jst; then
    echo "FAIL: GET support still present in ajaxSet_wireless_network_configuration.jst"
    exit 1
fi
if grep -q "\$_GET\['configInfo'\]" source/Styles/xb6/jst/actionHandler/ajaxSet_wireless_network_configuration_onewifi.jst; then
    echo "FAIL: GET support still present in ajaxSet_wireless_network_configuration_onewifi.jst"
    exit 1
fi
echo "PASS: GET support removed from both files"
