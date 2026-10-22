#!/bin/sh
if sed -n '1603p' source/Styles/xb3/config/php.ini | grep -q "session.entropy_file.*=.*dev/urandom"; then
    echo "PASS: session.entropy_file set to /dev/urandom"
else
    echo "FAIL: session.entropy_file not set to /dev/urandom"
    exit 1
fi
if sed -n '1607p' source/Styles/xb3/config/php.ini | grep -q "session.entropy_length.*=.*16"; then
    echo "PASS: session.entropy_length set to 16"
else
    echo "FAIL: session.entropy_length not set to 16"
    exit 1
fi
