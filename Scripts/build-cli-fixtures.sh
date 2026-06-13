#!/bin/sh
# Copyright (c) 2026 Roman Zhuzhgov
# Licensed under the Apache License, Version 2.0
#
# Builds the CLI test fixtures from the checked-in sources in
# Tests/Fixtures/CLI/src into Tests/Fixtures/CLI/bin. The artifacts are
# compiled from our own sources (never Apple-owned binaries), so they
# are redistributable and checked into the repository; this script
# exists so anyone can reproduce them.
#
# Regeneration requires macOS with the Xcode command-line tools (clang
# with -arch arm64/arm64e, lipo, strip). Output bytes are deterministic
# for a fixed toolchain: -Wl,-reproducible pins LC_UUID (otherwise
# random under ld-prime), and the linker's ad-hoc signature is a pure
# function of content + output filename. A different toolchain may
# shift code bytes, in which case the goldens under
# Tests/Fixtures/CLI/golden are re-locked from the rebuilt binaries —
# goldens normalize nothing but the fixture's path.
#
# Well-formed fixtures:
#   hello-arm64     thin arm64; symbols _add42/_sum_to/_helper/_main,
#                   function starts, bl call graph (hello.c, -O0)
#   hello-arm64e    same source at -arch arm64e (PAC prologues)
#   hello-fat       lipo of the two (slice-selection fixture)
#   hello-fat64     the same pair under 64-bit fat_arch_64 headers
#                   (cafebabf), exercising the fat64 walk path
#   hello-stripped  hello-arm64 with the symbol table stripped
#                   (function starts survive -> sub_<hex> labels)
#   stub-arm64      thin arm64 calling an external libc function
#                   (strcoll) so the linker emits a __stubs entry routed
#                   through the indirect symbol table; a branch to it
#                   annotates `; symbol stub for: _strcoll` (stub.c)
#   stub-stripped   stub-arm64 with the symbol table stripped — the
#                   import name still resolves through LC_DYSYMTAB's
#                   indirect symbol table (which strip preserves), so
#                   stub symbolication survives stripping
#   dic-arm64.o     assembly with .data_region markers -> real
#                   LC_DATA_IN_CODE (jump-table-8 + data kinds). Kept as
#                   MH_OBJECT deliberately: the current linker (ld-prime)
#                   drops data-in-code entries from linked arm64
#                   executables (only the deprecated -ld_classic keeps
#                   them), while assembler-emitted entries are stable.
#                   Note the offset convention split this fixture pins:
#                   image DICE offsets are file offsets from the mach
#                   header; MH_OBJECT DICE offsets are section-address-
#                   space values.
#   dic-linked      dic-arm64.o linked into an MH_EXECUTE image with
#                   -ld_classic (the one linker mode that preserves
#                   LC_DATA_IN_CODE), pinning the *file-offset* DICE
#                   convention of linked images against the MH_OBJECT
#                   fixture's section-address-space convention. If a
#                   future toolchain removes -ld_classic this step fails
#                   loudly; the checked-in binary remains valid.
#
# Malformed variants (byte surgery, documented inline below):
#   truncated-header    first 16 bytes of hello-arm64
#   lying-section       __text section_64.size inflated past the file
#   zero-size-section   __text section_64.size = 0
#   lying-nsects        __TEXT segment nsects inflated past its cmdsize
#   bad-symtab          LC_SYMTAB.symoff pointed past the file
#   bad-fnstarts        LC_FUNCTION_STARTS.dataoff pointed past the file
#   hostile-dic-entry   first data_in_code_entry.offset pointed outside
#                       every section (dic-arm64.o base)
#   hostile-dic-region  LC_DATA_IN_CODE.dataoff pointed past the file
#   fat-bad-slice       hello-fat with the second fat_arch.offset pointed
#                       past the file (selection falls back to slice 1)
#   fat-all-oob         hello-fat with BOTH fat_arch.offsets pointed past
#                       the file (no slice selectable -> the truncated-fat
#                       "slice content out of range" error, not "no slice")
#   bad-indirectsym     stub-arm64 with LC_DYSYMTAB.indirectsymoff pointed
#                       past the file (stub symbolication unavailable)
#   not-macho.txt       plain text (no magic)

set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/Tests/Fixtures/CLI/src"
bin="$root/Tests/Fixtures/CLI/bin"
CC="${CC:-clang}"

mkdir -p "$bin"

echo "building well-formed fixtures..."
"$CC" -arch arm64 -O0 -fno-stack-protector -Wl,-reproducible -o "$bin/hello-arm64" "$src/hello.c"
"$CC" -arch arm64e -O0 -fno-stack-protector -Wl,-reproducible -o "$bin/hello-arm64e" "$src/hello.c"
lipo -create -output "$bin/hello-fat" "$bin/hello-arm64" "$bin/hello-arm64e"
lipo -create -fat64 -output "$bin/hello-fat64" "$bin/hello-arm64" "$bin/hello-arm64e"
"$CC" -arch arm64 -O1 -fno-stack-protector -Wl,-reproducible -o "$bin/stub-arm64" "$src/stub.c"
strip -o "$bin/stub-stripped" "$bin/stub-arm64" 2> /dev/null
"$CC" -arch arm64 -c -o "$bin/dic-arm64.o" "$src/dic.s"
"$CC" -arch arm64 -Wl,-ld_classic -Wl,-reproducible -nostartfiles -Wl,-e,_main \
    -o "$bin/dic-linked" "$bin/dic-arm64.o"
strip -o "$bin/hello-stripped" "$bin/hello-arm64" 2> /dev/null

printf 'this is not a mach-o binary\n' > "$bin/not-macho.txt"

echo "applying byte surgery for malformed variants..."
python3 - "$bin" << 'PY'
import struct
import sys
import pathlib

bindir = pathlib.Path(sys.argv[1])

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29

def load_commands(buf):
    """Yield (offset, cmd, cmdsize) for each load command (thin, LE)."""
    ncmds = struct.unpack_from('<I', buf, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', buf, off)
        yield off, cmd, size
        off += size


def find_text_section(buf):
    """Byte offset of __TEXT,__text's section_64 header."""
    for off, cmd, size in load_commands(buf):
        if cmd != LC_SEGMENT_64:
            continue
        nsects = struct.unpack_from('<I', buf, off + 64)[0]
        for i in range(nsects):
            s = off + 72 + i * 80
            if buf[s:s + 16].rstrip(b'\0') == b'__text':
                return s
    raise SystemExit('fixture surgery: no __text section found')


def find_command(buf, target):
    """Byte offset of the first load command with cmd == target."""
    for off, cmd, size in load_commands(buf):
        if cmd == target:
            return off
    raise SystemExit('fixture surgery: no load command 0x%x' % target)


hello = bytearray((bindir / 'hello-arm64').read_bytes())
dic = bytearray((bindir / 'dic-arm64.o').read_bytes())
fat = bytearray((bindir / 'hello-fat').read_bytes())
stub = bytearray((bindir / 'stub-arm64').read_bytes())

# Sanity: dic-arm64.o must really carry LC_DATA_IN_CODE entries, or the
# fixture would silently stop testing the data-in-code path.
dic_cmd = find_command(dic, LC_DATA_IN_CODE)
dic_datasize = struct.unpack_from('<I', dic, dic_cmd + 12)[0]
if dic_datasize < 16:
    raise SystemExit('fixture surgery: dic-arm64.o has %d bytes of data-in-code, expected >= 16' % dic_datasize)

# truncated-header: cut mid-mach_header_64 (16 of 32 bytes).
(bindir / 'truncated-header').write_bytes(bytes(hello[:16]))

# lying-section: __text section_64.size (u64 at +40) inflated far past
# the file; the walker must clamp to the bytes that exist.
b = bytearray(hello)
struct.pack_into('<Q', b, find_text_section(b) + 40, 0x0000_0FFF_FFFF_0000)
(bindir / 'lying-section').write_bytes(bytes(b))

# zero-size-section: __text section_64.size = 0; nothing decodable.
b = bytearray(hello)
struct.pack_into('<Q', b, find_text_section(b) + 40, 0)
(bindir / 'zero-size-section').write_bytes(bytes(b))

# lying-nsects: __TEXT's segment_command_64.nsects (u32 at +64) = 1000,
# which cannot fit the command's cmdsize; the walker walks the budget.
b = bytearray(hello)
for off, cmd, size in load_commands(b):
    if cmd == LC_SEGMENT_64 and b[off + 8:off + 24].rstrip(b'\0') == b'__TEXT':
        struct.pack_into('<I', b, off + 64, 1000)
        break
(bindir / 'lying-nsects').write_bytes(bytes(b))

# bad-symtab: LC_SYMTAB.symoff (u32 at +8) pointed past the file.
b = bytearray(hello)
struct.pack_into('<I', b, find_command(b, LC_SYMTAB) + 8, 0xF000_0000)
(bindir / 'bad-symtab').write_bytes(bytes(b))

# bad-fnstarts: LC_FUNCTION_STARTS.dataoff (u32 at +8) pointed past the file.
b = bytearray(hello)
struct.pack_into('<I', b, find_command(b, LC_FUNCTION_STARTS) + 8, 0xF000_0000)
(bindir / 'bad-fnstarts').write_bytes(bytes(b))

# hostile-dic-entry: first data_in_code_entry.offset (u32) pointed at a
# file offset no code section contains; the entry must be dropped with
# a diagnostic, not invent a data word.
b = bytearray(dic)
dataoff = struct.unpack_from('<I', b, find_command(b, LC_DATA_IN_CODE) + 8)[0]
struct.pack_into('<I', b, dataoff, 0x00FF_0000)
(bindir / 'hostile-dic-entry').write_bytes(bytes(b))

# hostile-dic-region: LC_DATA_IN_CODE.dataoff pointed past the file;
# the whole table is ignored with a diagnostic.
b = bytearray(dic)
struct.pack_into('<I', b, find_command(b, LC_DATA_IN_CODE) + 8, 0xF000_0000)
(bindir / 'hostile-dic-region').write_bytes(bytes(b))

# fat-bad-slice: second fat_arch.offset (big-endian u32 at 8 + 20 + 8)
# pointed past the file; selection must diagnose and fall back to the
# remaining slice.
b = bytearray(fat)
struct.pack_into('>I', b, 8 + 20 + 8, 0xF000_0000)
(bindir / 'fat-bad-slice').write_bytes(bytes(b))

# fat-all-oob: BOTH fat_arch.offsets (big-endian u32 at 8+8 and 8+20+8)
# pointed past the file; no slice is selectable. The walker must report
# the truncated-fat "slice content out of range" cause, not a misleading
# "no slice for this architecture".
b = bytearray(fat)
struct.pack_into('>I', b, 8 + 8, 0xF000_0000)
struct.pack_into('>I', b, 8 + 20 + 8, 0xF000_0000)
(bindir / 'fat-all-oob').write_bytes(bytes(b))

# bad-indirectsym: LC_DYSYMTAB.indirectsymoff (u32 at +56) pointed past
# the file; stub symbolication is unavailable with a diagnostic, the
# listing still renders (the stub branch just shows no annotation).
LC_DYSYMTAB = 0xB
b = bytearray(stub)
struct.pack_into('<I', b, find_command(b, LC_DYSYMTAB) + 56, 0xF000_0000)
(bindir / 'bad-indirectsym').write_bytes(bytes(b))

print('surgery complete')
PY

echo "fixtures built:"
ls -l "$bin"

# Golden lock: render each well-formed fixture through the freshly built
# CLI and store the expected bytes. Invocations run from the repo root
# with repo-relative fixture paths, so the path echoed on the listing's
# first line is machine-independent; tests rewrite their absolute
# fixture prefix to the same relative form before comparing (the goldens
# themselves normalize nothing). Listings carry no UUIDs or timestamps.
echo "locking goldens..."
golden="$root/Tests/Fixtures/CLI/golden"
mkdir -p "$golden"
cd "$root"
swift build > /dev/null
iris="$root/.build/debug/iris"

"$iris" --color never Tests/Fixtures/CLI/bin/hello-arm64 > "$golden/hello-arm64.listing.txt"
"$iris" --color never Tests/Fixtures/CLI/bin/hello-arm64e > "$golden/hello-arm64e.listing.txt"
"$iris" --color never Tests/Fixtures/CLI/bin/hello-fat > "$golden/hello-fat.listing.txt"
"$iris" --color never Tests/Fixtures/CLI/bin/hello-stripped > "$golden/hello-stripped.listing.txt"
"$iris" --color never Tests/Fixtures/CLI/bin/stub-arm64 > "$golden/stub-arm64.listing.txt"
"$iris" --color never Tests/Fixtures/CLI/bin/stub-stripped > "$golden/stub-stripped.listing.txt"
"$iris" --json Tests/Fixtures/CLI/bin/stub-arm64 > "$golden/stub-arm64.ndjson"
"$iris" --color never Tests/Fixtures/CLI/bin/dic-arm64.o > "$golden/dic-arm64.listing.txt"
"$iris" --color never Tests/Fixtures/CLI/bin/dic-linked > "$golden/dic-linked.listing.txt"
"$iris" --color never --semantics Tests/Fixtures/CLI/bin/hello-arm64 > "$golden/hello-arm64.semantics.txt"
"$iris" --json Tests/Fixtures/CLI/bin/hello-arm64 > "$golden/hello-arm64.ndjson"
"$iris" stats Tests/Fixtures/CLI/bin/hello-arm64e > "$golden/hello-arm64e.stats.txt"
"$iris" stats --json Tests/Fixtures/CLI/bin/dic-linked > "$golden/dic-linked.stats.json"
# functions verb (per-function granularity): human summary and the
# "kind":"function" NDJSON for the thin, arm64e (PAC), stripped (sub_
# labels), and stub (adjacent-__stubs exclusion) shapes.
"$iris" functions --color never Tests/Fixtures/CLI/bin/hello-arm64 > "$golden/hello-arm64.functions.txt"
"$iris" functions --color never Tests/Fixtures/CLI/bin/hello-arm64e > "$golden/hello-arm64e.functions.txt"
"$iris" functions --color never Tests/Fixtures/CLI/bin/hello-stripped > "$golden/hello-stripped.functions.txt"
"$iris" functions --color never Tests/Fixtures/CLI/bin/stub-arm64 > "$golden/stub-arm64.functions.txt"
"$iris" functions --json Tests/Fixtures/CLI/bin/hello-arm64 > "$golden/hello-arm64.functions.ndjson"
"$iris" functions --json Tests/Fixtures/CLI/bin/hello-arm64e > "$golden/hello-arm64e.functions.ndjson"
"$iris" functions --json Tests/Fixtures/CLI/bin/stub-arm64 > "$golden/stub-arm64.functions.ndjson"

echo "goldens locked:"
ls -l "$golden"
