// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// CLI fixture source producing real LC_DATA_IN_CODE entries: the
// .data_region directives mark an embedded jump table (kind
// JUMP_TABLE8) and a raw data word (kind DATA) inside __text — the
// loader-level knowledge the disassembler must honor instead of
// decoding garbage. Self-contained (no external references) so the
// linked output is byte-stable for a given toolchain.
//
// Expected shape:
//   _main — mov w0, #0; ret
//   _pick — bounded dispatch through Ltable (4 x 1-byte entries),
//           cases 2 instructions apart from Lcase0
//   Ltable    — .data_region jt8: bytes 0, 2, 4, 6
//   Lliteral  — .data_region:     .long 0xdeadbeef
// Local (L-prefixed) labels do not reach the symbol table.

.text
.align 2

.globl _main
_main:
    mov w0, #0
    ret

.globl _pick
_pick:
    cmp w0, #3
    b.hi Ldefault
    adrp x1, Ltable@PAGE
    add x1, x1, Ltable@PAGEOFF
    ldrb w2, [x1, w0, uxtw]
    adr x3, Lcase0
    add x3, x3, x2, lsl #2
    br x3
Lcase0:
    mov w0, #10
    ret
    mov w0, #20
    ret
    mov w0, #30
    ret
Ldefault:
    mov w0, #99
    ret

    .p2align 2
Ltable:
    .data_region jt8
    .byte 0, 2, 4, 6
    .end_data_region
Lliteral:
    .data_region
    .long 0xdeadbeef
    .end_data_region
