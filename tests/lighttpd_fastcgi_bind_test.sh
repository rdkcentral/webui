#!/bin/sh
if grep -q '"host" => "127.0.0.1"' source/Styles/xb3/config/lighttpd.conf; then
    echo "PASS: FastCGI bound to localhost"
else
    echo "FAIL: FastCGI not bound to localhost"
    exit 1
fi
if grep -q '"host" => "0.0.0.0"' source/Styles/xb3/config/lighttpd.conf; then
    echo "FAIL: FastCGI still bound to 0.0.0.0"
    exit 1
else
    echo "PASS: No 0.0.0.0 binding found"
fi
