#!/bin/sh
if grep -q "include.*actionHandlerUtility.php" source/Styles/xb3/code/actionHandler/ajaxSet_wireless_network_configuration_redirection.php; then
    echo "PASS: actionHandlerUtility.php included (session auth from RDKEMW-25949)"
else
    echo "FAIL: actionHandlerUtility.php not included"
    exit 1
fi
