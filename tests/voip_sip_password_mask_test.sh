#!/bin/sh
if grep "Auth_pwd" source/Styles/xb3/code/Voip_SipBasic_ServiceProvider.php | grep -q "getStr"; then
    echo "FAIL: Auth_pwd still exposes password"
    exit 1
else
    echo "PASS: Auth_pwd does not expose password"
fi
