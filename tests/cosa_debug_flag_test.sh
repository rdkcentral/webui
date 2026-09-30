#!/bin/sh
if grep -q "st.st_uid == 0" source/CcspPhpExtension/cosa.c; then
    echo "PASS: root ownership check present"
else
    echo "FAIL: root ownership check missing"
    exit 1
fi
if grep -q "st.st_mode & 0222" source/CcspPhpExtension/cosa.c; then
    echo "PASS: world-writable check present"
else
    echo "FAIL: world-writable check missing"
    exit 1
fi
if grep -q "#include <sys/stat.h>" source/CcspPhpExtension/cosa.c; then
    echo "PASS: sys/stat.h included"
else
    echo "FAIL: sys/stat.h not included"
    exit 1
fi
