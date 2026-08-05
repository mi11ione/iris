// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Real `__TEXT,__text` for the benchmark battery.
//
// Every workload used to run on one synthetic buffer — a 3:1 mix of a
// twelve-word prologue template and SplitMix64 noise. That is fine for
// decode throughput, where what matters is that the words are real
// encodings, and wrong for anything sensitive to the SHAPE of real code.
// The operand-buffer reserve is sized from a corpus census of just over
// two operands per word; the synthetic buffer is nowhere near that, so a
// footprint measured on it reports the reserve as waste. Shipped code is
// the only honest input for that question.
//
// The bench parses the Mach-O header itself rather than reaching for the
// CLI's walker: that walker is deliberately not library API, and a
// benchmark is not a reason to make it one. Fifty lines of header reading
// here keeps the published surface exactly as it is.

import Foundation
import Iris

/// A code section lifted from a real Mach-O, ready to decode.
struct RealText {
    let path: String
    let bytes: [UInt8]
    let baseAddress: UInt64
    let isARM64E: Bool

    var wordCount: Int {
        bytes.count / 4
    }

    var features: Features {
        isARM64E ? .arm64e : []
    }
}

enum MachO {
    private static let magic64: UInt32 = 0xFEED_FACF
    private static let fatMagic: UInt32 = 0xCAFE_BABE
    private static let fatMagic64: UInt32 = 0xCAFE_BABF
    private static let segment64: UInt32 = 0x19
    private static let cpuTypeARM64: UInt32 = 0x0100_000C

    private static func u32(_ d: Data, _ o: Int, big: Bool = false) -> UInt32? {
        guard o >= 0, o + 4 <= d.count else { return nil }
        let v = d.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: o, as: UInt32.self) }
        return big ? v.bigEndian : v.littleEndian
    }

    private static func u64(_ d: Data, _ o: Int) -> UInt64? {
        guard o >= 0, o + 8 <= d.count else { return nil }
        return d.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: o, as: UInt64.self) }.littleEndian
    }

    /// The `__TEXT,__text` section of the arm64/arm64e slice, or `nil` when
    /// the file is not a Mach-O carrying one.
    static func text(at path: String) -> RealText? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        guard let head = u32(data, 0) else { return nil }

        // Fat: walk the arch table for an arm64 slice and recurse on its
        // offset. The fat header is big-endian on every host, so the raw
        // little-endian read is the byte-swapped magic — the thin header
        // below is host-order and is compared directly.
        if head.byteSwapped == fatMagic || head.byteSwapped == fatMagic64 {
            let is64 = head.byteSwapped == fatMagic64
            guard let count = u32(data, 4, big: true) else { return nil }
            let entrySize = is64 ? 32 : 20
            for i in 0 ..< Int(count) {
                let entry = 8 + i * entrySize
                guard let cpu = u32(data, entry, big: true), cpu == cpuTypeARM64 else { continue }
                // fat_arch offset is a 4-byte field at +8; fat_arch_64's is
                // 8 bytes at the same place. Both big-endian.
                let offset: UInt64? = is64
                    ? u64(data, entry + 8).map(\.byteSwapped)
                    : u32(data, entry + 8, big: true).map(UInt64.init)
                guard let sliceOffset = offset else { continue }
                return thin(data, base: Int(sliceOffset), path: path)
            }
            return nil
        }
        return thin(data, base: 0, path: path)
    }

    private static func thin(_ data: Data, base: Int, path: String) -> RealText? {
        guard u32(data, base) == magic64 else { return nil }
        guard let cpuSubtype = u32(data, base + 8),
              let commandCount = u32(data, base + 16)
        else { return nil }
        // ARM64E is subtype 2 in the low byte; the high bits are PAC ABI flags.
        let isARM64E = (cpuSubtype & 0xFF) == 2

        var cursor = base + 32 // mach_header_64 is 32 bytes
        for _ in 0 ..< Int(commandCount) {
            guard let kind = u32(data, cursor), let size = u32(data, cursor + 4), size >= 8
            else { return nil }
            if kind == segment64 {
                // segname is 16 bytes at +8; nsects at +64; sections start at +72.
                let name = segmentName(data, cursor + 8)
                if name == "__TEXT", let nsects = u32(data, cursor + 64) {
                    var section = cursor + 72
                    for _ in 0 ..< Int(nsects) {
                        if segmentName(data, section) == "__text",
                           let addr = u64(data, section + 32),
                           let sizeBytes = u64(data, section + 40),
                           let offset = u32(data, section + 48),
                           sizeBytes >= 4
                        {
                            let start = base + Int(offset)
                            let end = start + Int(sizeBytes)
                            guard start >= 0, end <= data.count else { return nil }
                            return RealText(
                                path: path,
                                bytes: [UInt8](data[start ..< end]),
                                baseAddress: addr,
                                isARM64E: isARM64E,
                            )
                        }
                        section += 80 // section_64
                    }
                }
            }
            cursor += Int(size)
        }
        return nil
    }

    /// A 16-byte fixed-width segment/section name, NUL-trimmed.
    private static func segmentName(_ d: Data, _ o: Int) -> String {
        guard o >= 0, o + 16 <= d.count else { return "" }
        var bytes: [UInt8] = []
        for i in 0 ..< 16 {
            let b = d[d.startIndex + o + i]
            if b == 0 { break }
            bytes.append(b)
        }
        return String(decoding: bytes, as: UTF8.self)
    }
}

/// The default corpus: shipped system binaries, largest first, skipping
/// anything unreadable. Real arm64e code with real operand density, which
/// is what the reserve and footprint questions need.
enum RealCorpus {
    static let candidates = [
        "/usr/lib/dyld",
        "/usr/bin/swift",
        "/usr/bin/git",
        "/bin/zsh",
        "/bin/ls",
    ]

    static func load(_ explicit: [String]) -> [RealText] {
        let paths = explicit.isEmpty ? candidates : explicit
        var out: [RealText] = []
        for p in paths {
            if let t = MachO.text(at: p), t.wordCount > 0 { out.append(t) }
        }
        return out.sorted { $0.wordCount > $1.wordCount }
    }
}
