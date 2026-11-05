#!/bin/sh
if sed -n '219p' source/Styles/xb3/config/lighttpd.conf | grep -q "^server.username"; then
    echo "PASS: server.username uncommented"
else
    echo "FAIL: server.username still commented"
    exit 1
fi
if sed -n '222p' source/Styles/xb3/config/lighttpd.conf | grep -q "^server.groupname"; then
    echo "PASS: server.groupname uncommented"
else
    echo "FAIL: server.groupname still commented"
    exit 1
fi
