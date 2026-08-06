// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

let svePatternText: [String] = [
    "pow2",
    "vl1", "vl2", "vl3", "vl4", "vl5", "vl6", "vl7", "vl8",
    "vl16", "vl32", "vl64", "vl128", "vl256",
    "#14", "#15", "#16", "#17", "#18", "#19", "#20", "#21",
    "#22", "#23", "#24", "#25", "#26", "#27", "#28",
    "mul4", "mul3", "all",
]

private func ptrue(pattern raw: UInt8) -> UInt32 {
    0x2518_E000 | (UInt32(raw) << 5)
}

private func patternText(_ raw: UInt8) -> String {
    Iris.decode(ptrue(pattern: raw)).text
}

/// Validates the count-pattern name table shared by PTRUE and the
/// element-count family.
@Suite("SVE predicate & control / count-pattern names")
struct SVEPatternNameTests {
    @Test func everyRawValueRendersItsText() {
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
