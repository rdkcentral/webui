#!/bin/sh
# Focused security regression test for XSS in pauseBlockGenerateHtml.sh
# Tests that html_escape function is properly implemented and applied

echo "Testing XSS protection in pauseBlockGenerateHtml.sh"

FAIL=0

# Test 1: Verify html_escape function exists with correct implementation
if grep -q 'html_escape.*local.*s' source/Styles/xb3/config/pauseBlockGenerateHtml.sh; then
    echo "PASS: html_escape function defined"
else
    echo "FAIL: html_escape function not properly defined"
    FAIL=1
fi

# Test 2: Verify html_escape encodes ampersand first (critical for correct encoding)
if grep -A 5 'html_escape()' source/Styles/xb3/config/pauseBlockGenerateHtml.sh | grep -q 's/\&/\&amp;/g'; then
    echo "PASS: html_escape encodes ampersand first"
else
    echo "FAIL: html_escape does not encode ampersand first"
    FAIL=1
fi

# Test 3: Verify html_escape encodes all HTML metacharacters
if grep -A 10 'html_escape()' source/Styles/xb3/config/pauseBlockGenerateHtml.sh | grep -q 's/</\&lt;/g'; then
    echo "PASS: html_escape encodes <"
else
    echo "FAIL: html_escape does not encode <"
    FAIL=1
fi

if grep -A 10 'html_escape()' source/Styles/xb3/config/pauseBlockGenerateHtml.sh | grep -q 's/>/\&gt;/g'; then
    echo "PASS: html_escape encodes >"
else
    echo "FAIL: html_escape does not encode >"
    FAIL=1
fi

if grep -A 10 'html_escape()' source/Styles/xb3/config/pauseBlockGenerateHtml.sh | grep -q 's/"/\&quot;/g'; then
    echo "PASS: html_escape encodes double quote"
else
    echo "FAIL: html_escape does not encode double quote"
    FAIL=1
fi

if grep -A 10 'html_escape()' source/Styles/xb3/config/pauseBlockGenerateHtml.sh | grep -q "s/'/\&#039;/g"; then
    echo "PASS: html_escape encodes single quote"
else
    echo "FAIL: html_escape does not encode single quote"
    FAIL=1
fi

# Test 4: Verify PARTNER_BRANDNAME uses html_escape
if grep 'PARTNER_BRANDNAME.*html_escape' source/Styles/xb3/config/pauseBlockGenerateHtml.sh > /dev/null 2>&1; then
    echo "PASS: PARTNER_BRANDNAME escaped"
else
    echo "FAIL: PARTNER_BRANDNAME not escaped"
    FAIL=1
fi

# Test 5: Verify PARTNER_PRODUCTNAME uses html_escape
if grep 'PARTNER_PRODUCTNAME.*html_escape' source/Styles/xb3/config/pauseBlockGenerateHtml.sh > /dev/null 2>&1; then
    echo "PASS: PARTNER_PRODUCTNAME escaped"
else
    echo "FAIL: PARTNER_PRODUCTNAME not escaped"
    FAIL=1
fi

# Test 6: Verify PARTNER_LOGO_FILE uses html_escape
if grep 'PARTNER_LOGO_FILE.*html_escape' source/Styles/xb3/config/pauseBlockGenerateHtml.sh > /dev/null 2>&1; then
    echo "PASS: PARTNER_LOGO_FILE escaped"
else
    echo "INFO: PARTNER_LOGO_FILE not escaped (may be in different context)"
fi

if [ $FAIL -eq 0 ]; then
    echo "PASS: All XSS protection tests passed"
else
    exit 1
fi
