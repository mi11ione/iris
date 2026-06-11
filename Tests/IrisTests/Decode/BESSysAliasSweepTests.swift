// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Sweeps the entire (op1, CRn, CRm, op2) key space of the SYS / SYSL /
/// SYSP encodings through the public decode + text path and proves, for
/// every key, the decode-to-text contract: alias-ness and alias kind are
/// inferred from the rendered shape at Rt = 0 / Rt = 31 (`name, xN` /
/// `name xN` / bare-at-xzr / optional-xN), the Rt semantic-read/write
/// gating matches the rendered shape, non-aliased keys fall back to the
/// generic `sys`/`sysl`/`sysp` tuple form, and the alias populations are
/// pinned (225 SYS / 2 SYSL / 120 SYSP rows).
@Suite("BES / SYS alias space — full key-space sweep")
struct BESSysAliasSweepTests {
    private struct Key: Hashable {
        let op1: UInt8, crn: UInt8, crm: UInt8, op2: UInt8
    }

    private static let allKeys: [Key] = {
        var keys: [Key] = []
        keys.reserveCapacity(8 * 16 * 16 * 8)
        for op1: UInt8 in 0 ... 7 {
            for crn: UInt8 in 0 ... 15 {
                for crm: UInt8 in 0 ... 15 {
                    for op2: UInt8 in 0 ... 7 {
                        keys.append(Key(op1: op1, crn: crn, crm: crm, op2: op2))
                    }
                }
            }
        }
        return keys
    }()

    private func sysWord(_ k: Key, rt: UInt32) -> UInt32 {
        0xD508_0000 | UInt32(k.op1) << 16 | UInt32(k.crn) << 12 | UInt32(k.crm) << 8 | UInt32(k.op2) << 5 | rt
    }

    private func syslWord(_ k: Key, rt: UInt32) -> UInt32 {
        0xD528_0000 | UInt32(k.op1) << 16 | UInt32(k.crn) << 12 | UInt32(k.crm) << 8 | UInt32(k.op2) << 5 | rt
    }

    private func syspWord(_ k: Key, rt: UInt32) -> UInt32 {
        0xD548_0000 | UInt32(k.op1) << 16 | UInt32(k.crn) << 12 | UInt32(k.crm) << 8 | UInt32(k.op2) << 5 | rt
    }

    @Test func sysSpaceSweepRendersAndGatesEveryRow() {
        var aliasCount = 0
        for k in Self.allKeys {
            let generic = "sys #\(k.op1), c\(k.crn), c\(k.crm), #\(k.op2)"
            let d0 = decode(sysWord(k, rt: 0))
            let d31 = decode(sysWord(k, rt: 31))
            #expect(d0.category == .branchesExceptionSystem)
            // The Rt = 31 rendering discriminates the row: the generic
            // tuple form means no alias; `name, xzr` a register alias;
            // `name xzr` a bare-register alias; a bare name an XZR-only
            // alias. Any other kind (e.g. an optional-register SYSL kind
            // leaking into SYS) breaks the shape assertions below.
            if d31.text == generic {
                // Generic SYS: Rt rendered (and read) only when != 31.
                #expect(d0.text == "\(generic), x0")
                #expect(d0.semanticReads.contains(.x(0)))
                #expect(d31.semanticReads.isEmpty)
                continue
            }
            aliasCount += 1
            if d31.text.hasSuffix(", xzr") {
                let name = String(d31.text.dropLast(5))
                #expect(!name.isEmpty)
                #expect(name == name.lowercased())
                #expect(d0.text == "\(name), x0")
                #expect(d0.semanticReads.contains(.x(0)))
                // Known anomaly: register-kind aliases at Rt=31 insert
                // `.xzr()` → bit 31 (the documented SP slot). Pinned
                // as-is; fixing is a deliberate behavior change.
                #expect(d31.semanticReads == RegisterSet(mask: 1 << 31))
            } else if d31.text.hasSuffix(" xzr") {
                let name = String(d31.text.dropLast(4))
                #expect(!name.isEmpty)
                #expect(name == name.lowercased())
                #expect(d0.text == "\(name) x0")
                #expect(d0.semanticReads.contains(.x(0)))
            } else {
                // XZR-only alias: bare name at Rt == 31; any other Rt
                // renders the generic form, but the operation still
                // ignores Rt, so the decoder records no Rt read.
                #expect(!d31.text.isEmpty)
                #expect(d31.text == d31.text.lowercased())
                #expect(d31.semanticReads.isEmpty)
                #expect(d0.text == "\(generic), x0")
                #expect(d0.semanticReads.isEmpty)
            }
        }
        #expect(aliasCount == 225, "SYS alias population drifted: \(aliasCount)")
    }

    @Test func syslSpaceSweepRendersAndGatesEveryRow() {
        var aliasCount = 0
        for k in Self.allKeys {
            let d0 = decode(syslWord(k, rt: 0))
            let d31 = decode(syslWord(k, rt: 31))
            #expect(d0.mnemonic == .sysl)
            if d0.text == "sysl x0, #\(k.op1), c\(k.crn), c\(k.crm), #\(k.op2)" {
                // Generic SYSL always renders and writes Rt (incl. xzr).
                #expect(d0.semanticWrites.contains(.x(0)))
                #expect(d31.text == "sysl xzr, #\(k.op1), c\(k.crn), c\(k.crm), #\(k.op2)")
                // Known anomaly: generic SYSL with Rt=31 inserts
                // `.xzr()` and so sets bit 31, which RegisterSet
                // documents as the SP slot. Pinned as-is; a fix is a
                // deliberate behavior change.
                #expect(d31.semanticWrites == RegisterSet(mask: 1 << 31))
                continue
            }
            aliasCount += 1
            // Every aliased SYSL row renders `name x0` at Rt = 0 and
            // writes Rt; an XZR-only kind leaking into SYSL would render
            // the generic form at Rt = 0 and trip the shape assertions.
            #expect(d0.text.hasSuffix(" x0"), "aliased SYSL must render the register: \(d0.text)")
            #expect(d0.semanticWrites.contains(.x(0)))
            let name = String(d0.text.dropLast(3))
            #expect(!name.isEmpty)
            if d31.text == name {
                // Optional-register alias: bare at XZR, and no Rt write.
                #expect(d31.semanticWrites.isEmpty)
            }
        }
        #expect(aliasCount == 2, "SYSL alias population drifted: \(aliasCount)")
    }

    @Test func syspSpaceSweepRendersEveryTLBIPRow() {
        var aliasCount = 0
        for k in Self.allKeys {
            let d = decode(syspWord(k, rt: 8))
            if d.text.hasPrefix("tlbip ") {
                aliasCount += 1
                #expect(d.mnemonic == .sysp)
                #expect(d.text.hasSuffix(", x8, x9"), "SYSP alias must render the pair: \(d.text)")
                #expect(d.semanticReads.contains(.x(8)) && d.semanticReads.contains(.x(9)))
            } else {
                // Non-aliased keys render the generic pair form (or are
                // honest UNDEFINED); a non-TLBIP alias row would render a
                // bare name here and fail loudly.
                #expect(d.text.hasPrefix("sysp ") || d.isUndefined, "unexpected SYSP rendering: \(d.text)")
            }
        }
        #expect(aliasCount == 120, "SYSP alias population drifted: \(aliasCount)")
    }

    @Test func knownAliasSpotRows() {
        // Literal pins, sourced from the ARM system-op tables.
        #expect(decode(sysWord(Key(op1: 0, crn: 7, crm: 1, op2: 0), rt: 31)).text == "ic ialluis")
        #expect(decode(sysWord(Key(op1: 0, crn: 7, crm: 5, op2: 0), rt: 31)).text == "ic iallu")
        #expect(decode(sysWord(Key(op1: 3, crn: 7, crm: 14, op2: 1), rt: 3)).text == "dc civac, x3")
        #expect(decode(sysWord(Key(op1: 0, crn: 7, crm: 8, op2: 0), rt: 0)).text == "at s1e1r, x0")
        #expect(decode(sysWord(Key(op1: 0, crn: 8, crm: 7, op2: 0), rt: 31)).text == "tlbi vmalle1")
        #expect(decode(sysWord(Key(op1: 3, crn: 7, crm: 2, op2: 7), rt: 0)).text == "trcit x0")
        #expect(decode(syslWord(Key(op1: 3, crn: 7, crm: 7, op2: 1), rt: 0)).text == "gcspopm x0")
        #expect(decode(syslWord(Key(op1: 3, crn: 7, crm: 7, op2: 1), rt: 31)).text == "gcspopm")
        #expect(decode(syslWord(Key(op1: 3, crn: 7, crm: 7, op2: 3), rt: 1)).text == "gcsss2 x1")
        #expect(decode(syspWord(Key(op1: 0, crn: 8, crm: 1, op2: 3), rt: 0)).text == "tlbip vaae1os, x0, x1")
    }
}
