#!/bin/sh
if [ -f source/CcspPhpApi/ccsptest.php ]; then
    echo "FAIL: ccsptest.php still present"
    exit 1
fi
echo "PASS: ccsptest.php removed (unauthenticated debug endpoint eliminated)"
