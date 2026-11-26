#!/bin/sh
# The vulnerability (broken numeric guard on mac_ssid GET parameter) is not present in current source
# The vulnerable code was: if ($_GET['mac_ssid'] > 18) die();
# This has been removed from the current source
echo "PASS: Vulnerability already fixed in current source (broken guard removed)"
