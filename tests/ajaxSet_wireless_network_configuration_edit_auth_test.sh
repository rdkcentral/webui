#!/bin/sh
# Focused security regression test for thisUser authorization validation
# Tests that thisUser is validated against loginuser in all handler variants

echo "Testing thisUser authorization validation"

FAIL=0

# Test 1: Verify xb3 JST variant
if grep -q "thisUser.*loginuser" source/Styles/xb3/jst/actionHandler/ajaxSet_wireless_network_configuration_edit.jst > /dev/null 2>&1; then
    echo "PASS: thisUser validation present in xb3 JST"
else
    echo "FAIL: thisUser validation missing in xb3 JST"
    FAIL=1
fi

# Test 2: Verify xb3 PHP variant
if grep -q "thisUser.*loginuser" source/Styles/xb3/code/actionHandler/ajaxSet_wireless_network_configuration_edit.php > /dev/null 2>&1; then
    echo "PASS: thisUser validation present in xb3 PHP"
else
    echo "FAIL: thisUser validation missing in xb3 PHP"
    FAIL=1
fi

# Test 3: Verify xb6 JST variant
if grep -q "thisUser.*loginuser" source/Styles/xb6/jst/actionHandler/ajaxSet_wireless_network_configuration_edit.jst > /dev/null 2>&1; then
    echo "PASS: thisUser validation present in xb6 JST"
else
    echo "FAIL: thisUser validation missing in xb6 JST"
    FAIL=1
fi

# Test 4: Verify xb6 OneWiFi JST variant
if grep -q "thisUser.*loginuser" source/Styles/xb6/jst/actionHandler/ajaxSet_wireless_network_configuration_edit_onewifi.jst > /dev/null 2>&1; then
    echo "PASS: thisUser validation present in xb6 OneWiFi JST"
else
    echo "FAIL: thisUser validation missing in xb6 OneWiFi JST"
    FAIL=1
fi

# Test 5: Verify xb6 PHP variant
if grep -q "thisUser.*loginuser" source/Styles/xb6/code/actionHandler/ajaxSet_wireless_network_configuration_edit.php > /dev/null 2>&1; then
    echo "PASS: thisUser validation present in xb6 PHP"
else
    echo "FAIL: thisUser validation missing in xb6 PHP"
    FAIL=1
fi

if [ $FAIL -eq 0 ]; then
    echo "PASS: All thisUser authorization validation tests passed"
else
    exit 1
fi
