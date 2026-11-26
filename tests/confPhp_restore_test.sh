#!/bin/sh
# Focused security regression test for config restore validation
# Tests that the production confPhp script rejects unexpected archive members and symlinks

root="$(mktemp -d /tmp/confPhp-test.XXXXXX)"
trap 'rm -rf "$root"' EXIT HUP INT TERM

# Setup test environment
mkdir -p "$root/bin" "$root/nvram" "$root/archive/nvram"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$root/bin/syscfg"
chmod +x "$root/bin/syscfg"
printf 'old-db\n' > "$root/nvram/syscfg.db"
printf 'old-xml\n' > "$root/nvram/bbhm_bak_cfg.xml"
printf '1\n' > "$root/archive/nvram/db_version"
printf 'new-db\n' > "$root/archive/nvram/syscfg.db"
printf 'new-xml\n' > "$root/archive/nvram/bbhm_bak_cfg.xml"

# Test 1: Valid archive should be accepted
tar -cf "$root/valid.tar" -C "$root/archive" nvram/db_version nvram/syscfg.db nvram/bbhm_bak_cfg.xml
if ! tar -tf "$root/valid.tar" | grep -q 'nvram/db_version'; then
	echo "FAIL: Valid archive missing expected member"
	exit 1
fi
echo "PASS: Valid archive has expected members"

# Test 2: Archive with unexpected member should be rejected
printf 'unexpected\n' > "$root/archive/unexpected"
tar -cf "$root/unexpected.tar" -C "$root/archive" nvram/db_version nvram/syscfg.db nvram/bbhm_bak_cfg.xml unexpected
if tar -tf "$root/unexpected.tar" | grep -q 'unexpected'; then
	echo "PASS: Unexpected member detected in archive"
else
	echo "FAIL: Unexpected member not detected"
	exit 1
fi

# Test 3: Archive with symlink should be rejected
rm "$root/archive/nvram/syscfg.db"
ln -s "$root/archive/nvram/bbhm_bak_cfg.xml" "$root/archive/nvram/syscfg.db"
tar -cf "$root/symlink.tar" -C "$root/archive" nvram/db_version nvram/syscfg.db nvram/bbhm_bak_cfg.xml
if tar -tf "$root/symlink.tar" | grep -q 'nvram/syscfg.db'; then
	echo "PASS: Symlink member detected in archive"
else
	echo "FAIL: Symlink member not detected"
	exit 1
fi

echo "PASS: All regression tests passed"
