#!/bin/sh
if grep "HostName" source/Styles/xb3/code/at_a_glance.php | grep -q "htmlspecialchars"; then
    echo "PASS: HostName HTML encoding present"
else
    echo "FAIL: HostName HTML encoding missing"
    exit 1
fi
