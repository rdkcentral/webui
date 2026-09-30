#!/bin/sh
if grep "network_pass" source/Styles/xb3/code/captiveportal.php | grep -q "echo"; then
    echo "FAIL: network_pass still echoed"
    exit 1
else
    echo "PASS: network_pass not echoed"
fi
if grep "network_pass1" source/Styles/xb3/code/captiveportal.php | grep -q "echo"; then
    echo "FAIL: network_pass1 still echoed"
    exit 1
else
    echo "PASS: network_pass1 not echoed"
fi
