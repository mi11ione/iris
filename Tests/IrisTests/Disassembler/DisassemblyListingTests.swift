// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `DisassemblyListing.render(_:)`. The contract is that line N is
/// exactly record N's ``Instruction/text``, so a listing and a
/// per-instruction.
@Suite("Disassembler / DisassemblyListing.render")
struct DisassemblyListingTests {
    private static func buffer(_ words: [UInt32]) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(words.count * 4)
        for word in words {
            bytes.append(UInt8(word & 0xFF))
            bytes.append(UInt8((word >> 8) & 0xFF))
            bytes.append(UInt8((word >> 16) & 0xFF))
            bytes.append(UInt8((word >> 24) & 0xFF))
        }
        return bytes
    }

    private static func expected(_ stream: InstructionStream) -> String {
        var text = ""
        for instruction in stream {
            text += instruction.text
            text += "\n"
        }
        return text
    }

    @Test func emptyStreamRendersEmpty() {
        let stream = InstructionStream(bytes: [] as [UInt8])
        #expect(DisassemblyListing.render(stream) == "")
    }

    @Test func lineNIsRecordNsText() {
        let stream = InstructionStream(bytes: Self.buffer([
            0xD503_201F,
            0x9100_0020,
            0xF940_07E0,
            0xD65F_03C0,
        ]))
        #expect(DisassemblyListing.render(stream) == Self.expected(stream))
    }

    @Test func undefinedRecordsContributeTheirOwnLine() {
        let stream = InstructionStream(bytes: Self.buffer([0x0000_0000, 0xFFFF_FFFF]))
        let rendered = DisassemblyListing.render(stream)
        #expect(rendered == Self.expected(stream))
        #expect(rendered.split(separator: "\n", omittingEmptySubsequences: false).count == 3)
    }

    @Test func widestScalableFormsRenderInFull() {
        let words: [UInt32] = [
            0xA149_8959,
            0xA14D_CD98,
            0xA10D_F23B,
        ]
        let stream = InstructionStream(bytes: Self.buffer(words + words + words + words))
        let rendered = DisassemblyListing.render(stream)
        #expect(rendered == Self.expected(stream))
        for instruction in stream {
            #expect(instruction.text.utf8.count >= 65)
        }
    }
}

/// Validates `Instruction.appendText(to:)`, the byte-path counterpart of
/// ``Instruction/text``.
@Suite("Disassembler / Instruction.appendText")
struct InstructionAppendTextTests {
    private func appended(_ instruction: Instruction) -> String {
        var out = TextBytes(capacity: 96)
        instruction.appendText(to: &out)
        return out.makeString()
    }

    @Test func matchesTextForEveryRecordShape() {
        let words: [UInt32] = [
            0xD503_201F,
            0x9100_0420,
            0xF940_07E0,
            0xD65F_03C0,
            0x0000_0000,
            0xFFFF_FFFF,
            0xA149_8959,
        ]
        for word in words {
            let instruction = decode(word)
            #expect(appended(instruction) == instruction.text,
                    "appendText diverged for 0x\(String(word, radix: 16))")
        }
    }

    @Test func appendsWithoutDisturbingWhatIsAlreadyBuffered() {
        var out = TextBytes(capacity: 96)
        out.put("prefix ")
        decode(0xD503_201F).appendText(to: &out)
        #expect(out.makeString() == "prefix nop")
    }
}
