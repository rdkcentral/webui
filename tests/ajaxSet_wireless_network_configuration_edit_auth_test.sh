#!/bin/sh
if grep -q "thisUser.*loginuser" source/Styles/xb3/jst/actionHandler/ajaxSet_wireless_network_configuration_edit.jst > /dev/null 2>&1; then
    echo "PASS: thisUser validation against loginuser present"
else
    echo "FAIL: thisUser validation missing"
    exit 1
fi
