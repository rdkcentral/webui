#!/bin/sh
if grep "REQUEST_METHOD" source/Styles/xb3/code/api.php | grep -q "_GET"; then
    echo "FAIL: REQUEST_METHOD still uses _GET"
    exit 1
else
    echo "PASS: REQUEST_METHOD uses _SERVER"
fi
if grep "REQUEST_METHOD" source/Styles/xb3/code/api.php | grep -q "_SERVER"; then
    echo "PASS: REQUEST_METHOD from _SERVER"
else
    echo "FAIL: REQUEST_METHOD not from _SERVER"
    exit 1
fi
