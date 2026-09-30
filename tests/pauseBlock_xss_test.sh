#!/bin/sh
if grep -q "html_escape" source/Styles/xb3/config/pauseBlockGenerateHtml.sh; then
    echo "PASS: html_escape function present"
else
    echo "FAIL: html_escape function missing"
    exit 1
fi
if grep "PARTNER_BRANDNAME.*html_escape" source/Styles/xb3/config/pauseBlockGenerateHtml.sh > /dev/null 2>&1; then
    echo "PASS: PARTNER_BRANDNAME escaped"
else
    echo "FAIL: PARTNER_BRANDNAME not escaped"
    exit 1
fi
if grep "PARTNER_PRODUCTNAME.*html_escape" source/Styles/xb3/config/pauseBlockGenerateHtml.sh > /dev/null 2>&1; then
    echo "PASS: PARTNER_PRODUCTNAME escaped"
else
    echo "FAIL: PARTNER_PRODUCTNAME not escaped"
    exit 1
fi
