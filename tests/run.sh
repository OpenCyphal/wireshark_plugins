#!/bin/sh
set -eu
export LC_ALL=C

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cy_root="$root/cy"
tshark_bin=${TSHARK:-$(command -v tshark || true)}
luac_bin=${LUAC:-$(command -v luac || true)}

if [ -z "$tshark_bin" ]; then
    echo "error: tshark 4.6 or newer is required (install the tshark package or set TSHARK)" >&2
    exit 2
fi

if [ -z "$luac_bin" ]; then
    echo "error: luac is required (install Lua 5.4 or set LUAC)" >&2
    exit 2
fi

version=$("$tshark_bin" --version | sed -n '1s/.* \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
major=${version%%.*}
minor=${version#*.}
if [ -z "$version" ] || [ "$major" -lt 4 ] || { [ "$major" -eq 4 ] && [ "$minor" -lt 6 ]; }; then
    echo "error: tshark 4.6 or newer is required; found ${version:-unknown}" >&2
    exit 2
fi

if [ ! -f "$cy_root/lib/libcanard/libcanard/canard.c" ] || \
   [ ! -f "$cy_root/lib/libudpard/libudpard/udpard.c" ] || \
   [ ! -f "$cy_root/lib/rapidhash.h" ]; then
    echo "error: Cy submodule is unavailable; run: git submodule update --init --recursive" >&2
    exit 2
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/cyphal-wireshark-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

${CC:-cc} -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$cy_root/lib/libcanard/libcanard" -I"$cy_root/lib" \
    "$root/tests/generate_can_vectors.c" "$cy_root/lib/libcanard/libcanard/canard.c" \
    -o "$tmp/generate_can_vectors"
"$tmp/generate_can_vectors" "$tmp/valid-can.pcap" "$tmp/invalid-can.pcap" "$tmp/vectors-manifest.tsv"

${CC:-cc} -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$cy_root/lib/libudpard/libudpard" -I"$cy_root/lib/libudpard/lib/cavl" -I"$cy_root/lib" \
    "$root/tests/generate_udp_vectors.c" "$cy_root/lib/libudpard/libudpard/udpard.c" \
    -o "$tmp/generate_udp_vectors"
"$tmp/generate_udp_vectors" "$tmp/valid-udp.pcap" "$tmp/invalid-udp.pcap" "$tmp/vectors-manifest.tsv"
"$luac_bin" -p "$root/cyphal_1v1.lua"

can_valid_fields='-e frame.number -e _ws.col.Source -e _ws.col.Destination -e cyphalcan11.version -e cyphal11.type -e cyphal11.scope -e cyphalcan11.crc_good -e cyphal11.expected_subject_id -e cyphal11.pinned -e cyphal11.name_hash_good -e _ws.col.Info'
can_invalid_fields='-e frame.number -e _ws.col.Source -e _ws.col.Destination -e cyphal11.type -e cyphalcan11.crc_good -e _ws.expert.message -e _ws.col.Info'

# shellcheck disable=SC2086
"$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'cyphal11 || (cyphalcan11.payload && cyphalcan11.eot)' -T fields \
    -E header=y -E separator=/t -E quote=n -E occurrence=f $can_valid_fields \
    >"$tmp/valid-can.tsv" 2>"$tmp/valid-can.stderr"
diff -u "$root/tests/expected-valid-can.tsv" "$tmp/valid-can.tsv"

"$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'frame.number == 2 || frame.number == 3 || frame.number == 24' -T fields \
    -E header=y -E separator=/t -E quote=n \
    -e frame.number -e _ws.col.Destination -e cyphalcan11.sot -e cyphalcan11.eot \
    -e cyphalcan11.fragment_index -e _ws.col.Info \
    >"$tmp/fragments-can.tsv" 2>"$tmp/fragments-can.stderr"
diff -u "$root/tests/expected-fragments-can.tsv" "$tmp/fragments-can.tsv"

# Exercise the non-heuristic Decode As registration as a separate pass.
# shellcheck disable=SC2086
"$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -d can.subdissector,cyphalcan11 \
    -Y 'cyphal11 || (cyphalcan11.payload && cyphalcan11.eot)' -T fields \
    -E header=y -E separator=/t -E quote=n -E occurrence=f $can_valid_fields \
    >"$tmp/decode-as.tsv" 2>"$tmp/decode-as.stderr"
diff -u "$root/tests/expected-valid-can.tsv" "$tmp/decode-as.tsv"

# shellcheck disable=SC2086
"$tshark_bin" -n -2 -r "$tmp/invalid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y '_ws.expert && cyphalcan11' -T fields \
    -E header=y -E separator=/t -E quote=n -E occurrence=a -E 'aggregator=|' $can_invalid_fields \
    >"$tmp/invalid-can.tsv" 2>"$tmp/invalid-can.stderr"
diff -u "$root/tests/expected-invalid-can.tsv" "$tmp/invalid-can.tsv"

udp_valid_fields='-e frame.number -e udp.dstport -e cyphaludp11.version -e cyphaludp11.priority -e cyphaludp11.transfer_id -e cyphaludp11.sender_uid -e cyphaludp11.frame_payload_offset -e cyphaludp11.transfer_payload_size -e cyphaludp11.header_crc32c_good -e cyphaludp11.prefix_crc32c_good -e cyphaludp11.sot -e cyphaludp11.eot -e cyphaludp11.duplicate -e cyphaludp11.session_color -e cyphal11.type -e cyphal11.scope -e cyphal11.expected_subject_id -e cyphal11.resolved_topic_name -e _ws.expert.message -e _ws.col.Info'
udp_invalid_fields='-e frame.number -e cyphaludp11.version -e cyphaludp11.header_crc32c_good -e cyphaludp11.prefix_crc32c_good -e cyphaludp11.void -e cyphaludp11.incompatibility -e cyphaludp11.frame_payload_offset -e cyphaludp11.transfer_payload_size -e cyphaludp11.reassembled_in -e _ws.expert.message -e _ws.col.Info'

# Multicast is registered directly on port 9382. The preference also enables
# CRC-guarded heuristic recognition of dynamically discovered unicast ports.
# shellcheck disable=SC2086
"$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y cyphaludp11 -T fields \
    -E header=y -E separator=/t -E quote=n -E occurrence=f $udp_valid_fields \
    >"$tmp/valid-udp.tsv" 2>"$tmp/valid-udp.stderr"
diff -u "$root/tests/expected-valid-udp.tsv" "$tmp/valid-udp.tsv"

# Exercise arbitrary-port UDP Decode As without heuristic recognition.
"$tshark_bin" -n -2 -r "$tmp/valid-udp.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -d udp.port==12000,cyphaludp11 -Y 'frame.number >= 6 && frame.number <= 11' -T fields \
    -e cyphal11.type >"$tmp/udp-decode-as.tsv" 2>"$tmp/udp-decode-as.stderr"
[ "$(tr '\n' ' ' <"$tmp/udp-decode-as.tsv")" = "2 3 4 5 6 7 " ]

# shellcheck disable=SC2086
"$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/invalid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y cyphaludp11 -T fields \
    -E header=y -E separator=/t -E quote=n -E occurrence=a -E 'aggregator=|' $udp_invalid_fields \
    >"$tmp/invalid-udp.tsv" 2>"$tmp/invalid-udp.stderr"
diff -u "$root/tests/expected-invalid-udp.tsv" "$tmp/invalid-udp.tsv"

types=$("$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y cyphal11 -T fields -e cyphal11.type | sort -nu | tr '\n' ' ')
[ "$types" = "0 1 2 3 4 5 6 7 8 9 " ]

resolved=$("$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'frame.number == 1 || frame.number == 25' -T fields -E separator=/t \
    -e frame.number -e cyphal11.resolved_topic_name)
[ "$resolved" = "$(printf '1\tplant/temperature\n25\tplant/temperature')" ]

links=$("$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'cyphalcan11.reassembled_in == 24' -T fields -e frame.number | wc -l)
[ "$links" -eq 23 ]

unclaimed=$("$tshark_bin" -n -2 -r "$tmp/invalid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'frame.number >= 11 && cyphalcan11' -T fields -e frame.number | wc -l)
[ "$unclaimed" -eq 0 ]

opaque=$("$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'frame.number == 1 || frame.number == 45' -T fields -E separator=/t \
    -e frame.number -e cyphal11.application_payload -e cyphalcan11.payload)
[ "$opaque" = "$(printf '1\t61626300000000\t\n45\t\tc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f')" ]

fd_modes=$("$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'frame.number == 1 || frame.number == 24' -T fields -E separator=/t \
    -e frame.number -e cyphalcan11.can_fd)
[ "$fd_modes" = "$(printf '1\tTrue\n24\tFalse')" ]

session_colors=$("$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'frame.number == 1 || frame.number == 2 || frame.number == 24 || frame.number == 25 || frame.number == 26' \
    -T fields -E separator=/t -e frame.number -e can.id -e cyphalcan11.session_color)
[ "$session_colors" = "$(printf '1\t280928170\t7\n2\t280928170\t7\n24\t280928170\t7\n25\t260031402\t4\n26\t260031402\t4')" ]

bad_session_colors=$("$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'cyphalcan11 && (!cyphalcan11.session_color || cyphalcan11.session_color < 1 || cyphalcan11.session_color > 10)' \
    -T fields -e frame.number | wc -l)
[ "$bad_session_colors" -eq 0 ]

valid_experts=$("$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'cyphalcan11 && _ws.expert' -T fields -e frame.number | wc -l)
[ "$valid_experts" -eq 0 ]

void_bytes=$("$tshark_bin" -n -2 -r "$tmp/valid-can.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'frame.number == 25' -T fields -e cyphal11.void)
[ "$void_bytes" = "aabbcc" ]

udp_types=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y cyphal11 -T fields -e cyphal11.type | sort -nu | tr '\n' ' ')
[ "$udp_types" = "0 1 2 3 4 5 6 7 8 9 " ]

udp_links=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y 'cyphaludp11.reassembled_in == 4' -T fields -e frame.number | wc -l)
[ "$udp_links" -eq 4 ]

udp_unclaimed=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/invalid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y 'frame.number == 11 && cyphaludp11' -T fields -e frame.number | wc -l)
[ "$udp_unclaimed" -eq 0 ]

udp_colors=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y 'frame.number == 1 || frame.number == 4 || frame.number == 6' \
    -T fields -E separator=/t -e frame.number -e cyphaludp11.session_color)
[ "$udp_colors" = "$(printf '1\t1\n4\t1\n6\t6')" ]

udp_bad_colors=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'cyphaludp11 && (!cyphaludp11.session_color || cyphaludp11.session_color < 1 || cyphaludp11.session_color > 10)' \
    -T fields -e frame.number | wc -l)
[ "$udp_bad_colors" -eq 0 ]

udp_payload=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y 'frame.number == 1' -T fields -e cyphal11.application_payload)
[ "$udp_payload" = "756470" ]

udp_logical_columns=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y 'frame.number == 1 || frame.number == 6 || frame.number == 13' \
    -T fields -E separator=/t -e cyphaludp11.logical_source -e cyphaludp11.logical_destination)
[ "$udp_logical_columns" = "$(printf '1122334455667788\tplant/temperature →S000e58cf\n1122334455667788\t192.0.2.20:12000\n1122334455667788\tS007ffe40/G1537')" ]

udp_redundant=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y 'frame.number >= 15 && frame.number <= 17' -T fields \
    -E separator=/t -e frame.number -e cyphaludp11.reassembled_in -e cyphal11.type)
[ "$udp_redundant" = "$(printf '15\t17\t\n16\t17\t\n17\t17\t1')" ]

udp_overlap=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y 'frame.number >= 18 && frame.number <= 20' -T fields \
    -E separator=/t -e frame.number -e cyphaludp11.reassembled_in -e cyphal11.type)
[ "$udp_overlap" = "$(printf '18\t20\t\n19\t20\t\n20\t20\t1')" ]

udp_duplicate_eot=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y 'frame.number == 21 || frame.number == 22 || frame.number == 24' \
    -T fields -E separator=/t -e frame.number -e cyphaludp11.duplicate -e cyphaludp11.reassembled_in -e cyphal11.type)
[ "$udp_duplicate_eot" = "$(printf '21\tFalse\t24\t\n22\tTrue\t\t\n24\tFalse\t24\t1')" ]

udp_buffer_limit=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true \
    -o cyphaludp11.max_buffered_bytes:500 -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" \
    -Y '(frame.number >= 2 && frame.number <= 5) && _ws.expert.message == "UDP reassembly memory limit exceeded"' \
    -T fields -e frame.number | tr '\n' ' ')
[ "$udp_buffer_limit" = "3 5 " ]

udp_fragment_limit=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true \
    -o cyphaludp11.max_fragments:2 -r "$tmp/valid-udp.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'frame.number == 4' -T fields -e _ws.expert.message)
[ "$udp_fragment_limit" = "UDP transfer exceeds the fragment-count limit" ]

udp_active_limit=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true \
    -o cyphaludp11.max_active_transfers:0 -r "$tmp/valid-udp.pcap" -X "lua_script:$root/cyphal_1v1.lua" \
    -Y 'frame.number == 1' -T fields -E separator=/t -e cyphal11.type -e _ws.expert.message)
[ "$udp_active_limit" = "$(printf '\tToo many active UDP transfers')" ]

udp_zero_cache=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true \
    -o cyphaludp11.max_cached_payload_bytes:0 -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y 'frame.number == 4 || frame.number == 17 || frame.number == 20 || frame.number == 24' \
    -T fields -E separator=/t -e frame.number -e cyphal11.type -e _ws.col.Info)
[ "$udp_zero_cache" = "$(printf '4\t1\t… ⛓ REL prio=4 tid=1108152157442 T3cfd10b3c63cdbc1@S000e58cf tag=8877665544332211 1100 B …\n17\t1\t… ⛓ REL prio=3 tid=57476735728782 T3cfd10b3c63cdbc1@S000e58cf tag=abcdef0123456789 1076 B\n20\t1\t… ⛓ REL prio=4 tid=1108152157459 T3cfd10b3c63cdbc1@S000e58cf tag=abcdef0123456790 1000 B …\n24\t1\t… ⛓ REL prio=4 tid=1108152157460 T3cfd10b3c63cdbc1@S000e58cf tag=abcdef0123456791 1000 B …')" ]

udp_valid_experts=$("$tshark_bin" -n -2 -o udp.try_heuristic_first:true -r "$tmp/valid-udp.pcap" \
    -X "lua_script:$root/cyphal_1v1.lua" -Y 'cyphaludp11 && _ws.expert' -T fields -e frame.number | wc -l)
[ "$udp_valid_experts" -eq 0 ]

if grep -R "Lua Error" "$tmp"/*.stderr "$tmp"/*.tsv >/dev/null; then
    echo "error: Wireshark reported a Lua error" >&2
    exit 1
fi

echo "Cyphal dissector tests passed with tshark $version"
