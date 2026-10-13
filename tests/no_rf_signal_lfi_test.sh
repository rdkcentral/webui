#!/bin/sh
if grep -q 'lang.*==.*eng.*||.*lang.*==.*fre' source/Styles/xb3/code/no_rf_signal.php; then
    echo "PASS: lang input validation present"
else
    echo "FAIL: lang input validation missing"
    exit 1
fi
if grep -q 'SESSION.*lang.*!=.*eng.*&&.*SESSION.*lang.*!=.*fre' source/Styles/xb3/code/no_rf_signal.php; then
    echo "PASS: session lang sanitization present"
else
    echo "FAIL: session lang sanitization missing"
    exit 1
fi
if grep -q 'defaultLanguage.*!=.*eng.*&&.*defaultLanguage.*!=.*fre' source/Styles/xb3/code/no_rf_signal.php; then
    echo "PASS: defaultLanguage sanitization present"
else
    echo "FAIL: defaultLanguage sanitization missing"
    exit 1
fi
