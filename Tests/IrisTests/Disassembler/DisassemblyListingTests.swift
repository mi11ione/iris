// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `DisassemblyListing.render(_:)` — the whole-stream text
/// entry point. The contract it has to hold is that line N is exactly
/// record N's ``Instruction/text``, so a listing and a per-instruction
/// render can never disagree, including for the records that render
/// empty and for the scalable multi-vector forms whose text is far wider
/// than the mean.
@Suite("Disassembler / DisassemblyListing.render")
struct DisassemblyListingTests {
    /// Little-endian bytes for `words`.
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
            0xD503_201F, // nop
            0x9100_0020, // add x0, x1, #0
            0xF940_07E0, // ldr x0, [sp, #8]
            0xD65F_03C0, // ret
        ]))
        #expect(DisassemblyListing.render(stream) == Self.expected(stream))
    }

    @Test func undefinedRecordsContributeTheirOwnLine() {
        // 0x00000000 is UDF #0; an unallocated word renders `.long`.
        let stream = InstructionStream(bytes: Self.buffer([0x0000_0000, 0xFFFF_FFFF]))
        let rendered = DisassemblyListing.render(stream)
        #expect(rendered == Self.expected(stream))
        #expect(rendered.split(separator: "\n", omittingEmptySubsequences: false).count == 3)
    }

    /// The widest text the ISA produces is a scalable multi-vector
    /// contiguous load at 66 bytes, well past the per-record mean the
    /// listing buffer is sized from, so a stream of them forces the
    /// buffer to grow while it is already carrying rendered text.
    @Test func widestScalableFormsRenderInFull() {
        let words: [UInt32] = [
            0xA149_8959, // ldnt1b { z17.b, z21.b, z25.b, z29.b }, pn10/z, [x10, #-28, mul vl]
            0xA14D_CD98, // ldnt1w { z16.s, z20.s, z24.s, z28.s }, pn11/z, [x12, #-12, mul vl]
            0xA10D_F23B, // ldnt1d { z19.d, z23.d, z27.d, z31.d }, pn12/z, [x17, x13, lsl #3]
        ]
        let stream = InstructionStream(bytes: Self.buffer(words + words + words + words))
        let rendered = DisassemblyListing.render(stream)
        #expect(rendered == Self.expected(stream))
        for instruction in stream {
            #expect(instruction.text.utf8.count >= 65)
        }
    }
}

/// Validates `Instruction.appendText(to:)` — the byte-path counterpart of
/// ``Instruction/text``. A caller assembling a larger document appends
/// into its own buffer instead of constructing a `String` per record, so
/// the two have to produce the same bytes for every record shape.
@Suite("Disassembler / Instruction.appendText")
struct InstructionAppendTextTests {
    private func appended(_ instruction: Instruction) -> String {
        var out = TextBytes(capacity: 96)
        instruction.appendText(to: &out)
        return out.makeString()
    }

    @Test func matchesTextForEveryRecordShape() {
        let words: [UInt32] = [
            0xD503_201F, // nop — no operands
            0x9100_0420, // add x0, x1, #1
            0xF940_07E0, // ldr x0, [sp, #8]
            0xD65F_03C0, // ret
            0x0000_0000, // udf #0
            0xFFFF_FFFF, // unallocated — renders .long
            0xA149_8959, // a 66-byte scalable multi-vector form
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
