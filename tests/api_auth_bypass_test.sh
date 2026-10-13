#!/bin/sh
if grep -q "EnableAPISecurity" source/Styles/xb3/code/api.php; then
    echo "FAIL: EnableAPISecurity bypass still present"
    exit 1
else
    echo "PASS: EnableAPISecurity bypass removed"
fi
if grep -q "authenticateCaller" source/Styles/xb3/code/api.php; then
    echo "PASS: authenticateCaller function present"
else
    echo "FAIL: authenticateCaller function missing"
    exit 1
fi
