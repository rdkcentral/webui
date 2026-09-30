#!/bin/sh
# Focused security regression test for JS injection vulnerability
# Tests that eval() is replaced with JSON.parse and proper encoding is applied

echo "Testing JS injection protection in connected_devices_computers.php"

# Test 1: Verify eval() is not used for device info parsing
if grep -q "eval.*name" source/Styles/xb3/code/connected_devices_computers.php; then
    echo "FAIL: eval() still used for name parsing"
    exit 1
else
    echo "PASS: eval() not used for name parsing"
fi

# Test 2: Verify JSON.parse is used
if ! grep -q "JSON.parse.*name" source/Styles/xb3/code/connected_devices_computers.php; then
    echo "FAIL: JSON.parse not used for name parsing"
    exit 1
else
    echo "PASS: JSON.parse used for name parsing"
fi

# Test 3: Verify htmlspecialchars(json_encode()) is used for name attributes
if ! grep -q "htmlspecialchars(json_encode.*name" source/Styles/xb3/code/connected_devices_computers.php; then
    echo "FAIL: htmlspecialchars(json_encode()) not used for name attributes"
    exit 1
else
    echo "PASS: htmlspecialchars(json_encode()) used for name attributes"
fi

# Test 4: Verify JSON.stringify is used for device editing
if ! grep -q "JSON.stringify" source/Styles/xb3/code/connected_devices_computers.php; then
    echo "FAIL: JSON.stringify not used for device editing"
    exit 1
else
    echo "PASS: JSON.stringify used for device editing"
fi

# Test 5: Verify ENT_QUOTES is used for HostName and Comments
if ! grep -q "HostName.*ENT_QUOTES" source/Styles/xb3/code/connected_devices_computers.php; then
    echo "FAIL: ENT_QUOTES not used for HostName"
    exit 1
else
    echo "PASS: ENT_QUOTES used for HostName"
fi

if ! grep -q "Comments.*ENT_QUOTES" source/Styles/xb3/code/connected_devices_computers.php; then
    echo "FAIL: ENT_QUOTES not used for Comments"
    exit 1
else
    echo "PASS: ENT_QUOTES used for Comments"
fi

# Test 6: Verify htmlspecialchars is applied to embedded JavaScript arrays
if ! grep -q "htmlspecialchars(json_encode.*online" source/Styles/xb3/code/connected_devices_computers.php; then
    echo "FAIL: htmlspecialchars not applied to online device arrays"
    exit 1
else
    echo "PASS: htmlspecialchars applied to online device arrays"
fi

if ! grep -q "htmlspecialchars(json_encode.*offline" source/Styles/xb3/code/connected_devices_computers.php; then
    echo "FAIL: htmlspecialchars not applied to offline device arrays"
    exit 1
else
    echo "PASS: htmlspecialchars applied to offline device arrays"
fi

echo "PASS: All JS injection protection tests passed"
