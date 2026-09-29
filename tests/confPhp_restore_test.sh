#!/bin/sh
root="$(mktemp -d /tmp/confPhp-test.XXXXXX)"
trap 'rm -rf "$root"' EXIT HUP INT TERM
mkdir -p "$root/bin" "$root/nvram" "$root/archive/nvram"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$root/bin/syscfg"
chmod +x "$root/bin/syscfg"
printf 'old-db\n' > "$root/nvram/syscfg.db"
printf 'old-xml\n' > "$root/nvram/bbhm_bak_cfg.xml"
printf '1\n' > "$root/archive/nvram/db_version"
printf 'new-db\n' > "$root/archive/nvram/syscfg.db"
printf 'new-xml\n' > "$root/archive/nvram/bbhm_bak_cfg.xml"
tar -cf "$root/valid.tar" -C "$root/archive" nvram/db_version nvram/syscfg.db nvram/bbhm_bak_cfg.xml
archive="$root/valid.tar"
tmpdir="$(mktemp -d "$root/tmp-confPhp.XXXXXX")" || exit 1
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM
db_version_found=0
syscfg_found=0
bbhm_found=0
while IFS= read -r member; do
	case "$member" in
		nvram/db_version|./nvram/db_version)
			[ "$db_version_found" = "0" ] || exit 1
			db_version_found=1
			;;
		nvram/syscfg.db|./nvram/syscfg.db)
			[ "$syscfg_found" = "0" ] || exit 1
			syscfg_found=1
			;;
		nvram/bbhm_bak_cfg.xml|./nvram/bbhm_bak_cfg.xml)
			[ "$bbhm_found" = "0" ] || exit 1
			bbhm_found=1
			;;
		*)
			exit 1
			;;
	esac
done <<EOF
$(tar -tf "$archive")
EOF
if [ "$db_version_found" != "1" ] || [ "$syscfg_found" != "1" ] || [ "$bbhm_found" != "1" ]; then
	exit 1
fi
if ! tar -xf "$archive" -C "$tmpdir" || [ -L "$tmpdir/nvram/db_version" ] || [ -L "$tmpdir/nvram/syscfg.db" ] || [ -L "$tmpdir/nvram/bbhm_bak_cfg.xml" ] || [ ! -f "$tmpdir/nvram/db_version" ] || [ ! -f "$tmpdir/nvram/syscfg.db" ] || [ ! -f "$tmpdir/nvram/bbhm_bak_cfg.xml" ]; then
	exit 1
fi
if ! cp "$tmpdir/nvram/syscfg.db" "$root/nvram/syscfg.db" || ! cp "$tmpdir/nvram/bbhm_bak_cfg.xml" "$root/nvram/bbhm_bak_cfg.xml"; then
	exit 1
fi
rm -rf "$tmpdir"
trap - EXIT HUP INT TERM
if [ "$(cat "$root/nvram/syscfg.db")" != "new-db" ] || [ "$(cat "$root/nvram/bbhm_bak_cfg.xml")" != "new-xml" ]; then
	exit 1
fi
printf 'unexpected\n' > "$root/archive/unexpected"
tar -cf "$root/unexpected.tar" -C "$root/archive" nvram/db_version nvram/syscfg.db nvram/bbhm_bak_cfg.xml unexpected
archive="$root/unexpected.tar"
tmpdir="$(mktemp -d "$root/tmp-confPhp.XXXXXX")" || exit 1
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM
db_version_found=0
syscfg_found=0
bbhm_found=0
unexpected_found=0
while IFS= read -r member; do
	case "$member" in
		nvram/db_version|./nvram/db_version)
			[ "$db_version_found" = "0" ] || exit 1
			db_version_found=1
			;;
		nvram/syscfg.db|./nvram/syscfg.db)
			[ "$syscfg_found" = "0" ] || exit 1
			syscfg_found=1
			;;
		nvram/bbhm_bak_cfg.xml|./nvram/bbhm_bak_cfg.xml)
			[ "$bbhm_found" = "0" ] || exit 1
			bbhm_found=1
			;;
		*)
			unexpected_found=1
			;;
	esac
done <<EOF
$(tar -tf "$archive")
EOF
if [ "$unexpected_found" = "1" ]; then
	exit 0
fi
exit 1
rm "$root/archive/nvram/syscfg.db"
ln -s "$root/archive/nvram/bbhm_bak_cfg.xml" "$root/archive/nvram/syscfg.db"
tar -cf "$root/symlink.tar" -C "$root/archive" nvram/db_version nvram/syscfg.db nvram/bbhm_bak_cfg.xml
archive="$root/symlink.tar"
tmpdir="$(mktemp -d "$root/tmp-confPhp.XXXXXX")" || exit 1
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM
db_version_found=0
syscfg_found=0
bbhm_found=0
while IFS= read -r member; do
	case "$member" in
		nvram/db_version|./nvram/db_version)
			[ "$db_version_found" = "0" ] || exit 1
			db_version_found=1
			;;
		nvram/syscfg.db|./nvram/syscfg.db)
			[ "$syscfg_found" = "0" ] || exit 1
			syscfg_found=1
			;;
		nvram/bbhm_bak_cfg.xml|./nvram/bbhm_bak_cfg.xml)
			[ "$bbhm_found" = "0" ] || exit 1
			bbhm_found=1
			;;
		*)
			break
			;;
	esac
done <<EOF
$(tar -tf "$archive")
EOF
if [ "$db_version_found" = "1" ] || [ "$syscfg_found" = "1" ] || [ "$bbhm_found" = "1" ]; then
	exit 1
fi
if ! tar -xf "$archive" -C "$tmpdir" || [ -L "$tmpdir/nvram/db_version" ] || [ -L "$tmpdir/nvram/syscfg.db" ] || [ -L "$tmpdir/nvram/bbhm_bak_cfg.xml" ] || [ ! -f "$tmpdir/nvram/db_version" ] || [ ! -f "$tmpdir/nvram/syscfg.db" ] || [ ! -f "$tmpdir/nvram/bbhm_bak_cfg.xml" ]; then
	exit 0
fi
exit 1
