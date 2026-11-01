#!/bin/sh
# Minimal TCP DNS fixture for bootstrap.test; no external/provider services.
set -eu
query=$(mktemp)
response=$(mktemp)
trap 'rm -f "$query" "$response"' EXIT
dd bs=1 count=2 of="$query" 2>/dev/null
length=$(od -An -tu1 "$query" | awk '{print $1*256+$2}')
[ "$length" -ge 12 ] && [ "$length" -le 512 ]
dd bs=1 count="$length" of="$query" 2>/dev/null
total=$((length + 16))
printf "\\$(printf '%03o' $((total / 256)))\\$(printf '%03o' $((total % 256)))" > "$response"
{
    dd if="$query" bs=1 count=2 2>/dev/null
    printf '\201\200\000\001\000\001\000\000\000\000'
    dd if="$query" bs=1 skip=12 2>/dev/null
    printf '\300\014\000\001\000\001\000\000\000\000\000\004\300\000\002\173'
} >> "$response"
cat "$response"
