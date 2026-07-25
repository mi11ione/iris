// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// The text the reference assembler prints for each 5-bit count-pattern value,
/// indexed by the raw field value. All 32 values are valid encodings — there is
/// no hole — but only 17 have a keyword; the fifteen in the middle have no name
/// and print as a plain decimal immediate instead.
let svePatternText: [String] = [
    "pow2",
    "vl1", "vl2", "vl3", "vl4", "vl5", "vl6", "vl7", "vl8",
    "vl16", "vl32", "vl64", "vl128", "vl256",
    "#14", "#15", "#16", "#17", "#18", "#19", "#20", "#21",
    "#22", "#23", "#24", "#25", "#26", "#27", "#28",
    "mul4", "mul3", "all",
]

/// PTRUE with the pattern field in bits[9:5]. PTRUE carries no multiplier, so
/// the pattern is the only variable in its text — which makes it the direct
/// probe for the shared count-pattern table.
private func ptrue(pattern raw: UInt8) -> UInt32 {
    0x2518_E000 | (UInt32(raw) << 5)
}

private func patternText(_ raw: UInt8) -> String {
    Iris.decode(ptrue(pattern: raw)).text
}

/// Validates the 5-bit count-pattern name table shared by PTRUE and the whole
/// element-count family. A missing keyword or a wrongly-named one is invisible
/// to the decoder and only shows up as wrong disassembly text, so the table is
/// pinned value by value through the rendered instruction.
@Suite("SVE predicate & control / count-pattern names")
struct SVEPatternNameTests {
    @Test func everyRawValueRendersItsText() {
        // `all` (31) is the assembler default and elides here, so it is pinned
        // separately below.
        for raw in UInt8(0) ... 30 {
            #expect(patternText(raw) == "ptrue p0.b, \(svePatternText[Int(raw)])",
                    "pattern \(raw)")
        }
    }

    @Test func theTableCoversTheWholeFiveBitRange() {
        #expect(svePatternText.count == 32)
        #expect(Set(svePatternText).count == 32, "every pattern renders distinctly")
    }

    @Test func theUnnamedMiddleRangeRendersAsADecimalImmediate() {
        for raw in UInt8(14) ... 28 {
            #expect(patternText(raw) == "ptrue p0.b, #\(raw)")
        }
    }

    @Test func onlyTheAllPatternIsTheElidedDefault() {
        #expect(patternText(31) == "ptrue p0.b", "the all pattern elides")
        for raw in UInt8(0) ... 30 {
            #expect(patternText(raw) != "ptrue p0.b", "pattern \(raw) must render")
        }
    }
}
