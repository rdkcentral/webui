#!/bin/sh
if grep -q 'CONF_FILENAME.*"/etc/ccsp_msg.cfg"' source/CcspPhpExtension/php_cosa.h; then
    echo "PASS: CONF_FILENAME points to /etc"
else
    echo "FAIL: CONF_FILENAME not pointing to /etc"
    exit 1
fi
if grep -q 'CONF_FILENAME.*"/tmp/' source/CcspPhpExtension/php_cosa.h; then
    echo "FAIL: CONF_FILENAME still points to /tmp"
    exit 1
else
    echo "PASS: No /tmp path in CONF_FILENAME"
fi
