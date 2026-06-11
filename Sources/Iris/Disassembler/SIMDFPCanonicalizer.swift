// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Text canonicalizer for SIMD/FP instructions.
// Produces lowercase llvm-mc-style text suitable for the golden-corpus
// parity diff. Element-subscript operands render as `Vn.<size>[i]` with
// the element-size suffix derived from `arrangement.elementSize` (never
// `Vn.<arrangement>[i]`). Leading runs of `.vectorRegister` operands are
// grouped into curly-brace lists for NEON LD/ST (LD1-4 / ST1-4 / LDxR /
// TBL / TBX).

enum SIMDFPCanonicalizer {
    @_optimize(speed)
    static func format(_ instruction: Instruction) -> String {
        if instruction.mnemonic == .undefined {
            return ""
        }
        // Crypto encodings flow through SIMDAndFPDecoder's delegation and
        // produce crypto-range mnemonics; route them to their canonicalizer.
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) {
            return CryptoAppleExtensionsCanonicalizer.format(instruction)
        }
        let mnemonicText = instruction.mnemonic.name
        let listSize = vectorListSize(mnemonic: instruction.mnemonic, operandCount: instruction.operands.count)
        let listIsLeading = listGroupingIsLeading(mnemonic: instruction.mnemonic)
        var renderedOps: [String] = []
        renderedOps.reserveCapacity(instruction.operands.count)
        var index = 0
        if listIsLeading, listSize > 0 {
            renderedOps.append(formatVectorList(instruction.operands, start: 0, count: listSize))
            index = listSize
        }
        while index < instruction.operands.count {
            // For TBL/TBX the list is at operands[1..1+listSize-1]; render
            // it as a group.
            if !listIsLeading, listSize > 0, index == 1 {
                renderedOps.append(formatVectorList(instruction.operands, start: 1, count: listSize))
                index += listSize
                continue
            }
            renderedOps.append(operandText(instruction.operands[index]))
            index += 1
        }
        if renderedOps.isEmpty {
            return mnemonicText
        }
        return "\(mnemonicText) \(renderedOps.joined(separator: ", "))"
    }

    /// Number of leading `.vectorRegister` operands that should be
    /// rendered as a single curly-brace list. Returns 0 when the mnemonic
    /// has no list operand, per the table below.
    @_effects(readonly)
    private static func vectorListSize(
        mnemonic: Mnemonic, operandCount: Int,
    ) -> Int {
        switch mnemonic {
        case .ld1, .st1, .ld2, .st2, .ld3, .st3, .ld4, .st4, .ldap1, .stl1:
            // Multi-structure / single-structure: operandCount - 1 vector
            // registers + 1 memory operand. The list-size depends on the
            // (selem, rpt) — derivable as operandCount minus the trailing
            // memory operand minus any post-index extra operand.
            max(0, operandCount - 1)
        case .ld1r, .ld2r, .ld3r, .ld4r:
            max(0, operandCount - 1)
        case .tbl, .tbx, .luti2, .luti4:
            // List is non-leading: operandCount = 1 (Vd) + N (list) + 1 (index).
            max(0, operandCount - 2)
        default:
            0
        }
    }

    @_effects(readonly)
    private static func listGroupingIsLeading(mnemonic: Mnemonic) -> Bool {
        switch mnemonic {
        case .tbl, .tbx, .luti2, .luti4: false
        default: true
        }
    }

    @_effects(readonly)
    private static func formatVectorList(
        _ operands: Instruction.Operands, start: Int, count: Int,
    ) -> String {
        var parts: [String] = []
        parts.reserveCapacity(count)
        var trailingIndex: String?
        for i in 0 ..< count {
            let op = operands[start + i]
            // Single-structure single-element lists (LD1/ST1 .. LD4/ST4
            // single-element) render the lane index once *after* the closing
            // brace — `{ v0.b, v1.b }[i]` — not per-element.
            if case let .vectorRegister(vr) = op, case let .element(arrangement, idx) = vr.view {
                parts.append("v\(vr.registerIndex).\(scalarSuffix(arrangement.elementSize))")
                trailingIndex = "[\(idx)]"
            } else {
                parts.append(operandText(op))
            }
        }
        let list = "{ \(parts.joined(separator: ", ")) }"
        return trailingIndex.map { list + $0 } ?? list
    }

    @_effects(readonly)
    private static func operandText(_ op: Operand) -> String {
        switch op {
        case let .vectorRegister(vr):
            return vectorRegisterText(vr)
        case let .register(r):
            return r.name
        case let .floatImmediate(bits, kind):
            return floatImmediateText(bits: bits, kind: kind)
        case let .unsignedImmediate(value, width):
            // The 64-bit MOVI replicated-byte immediate (the only width-64
            // SIMD immediate). llvm-mc renders a zero value as 16 plain hex
            // digits with no `0x`; a nonzero value as `0x` + hex zero-padded
            // to 14 digits (16 when bits[63:56] are set). Everything else
            // is decimal.
            if width == 64 {
                if value == 0 { return "#0000000000000000" }
                let digits = (value >> 56) != 0 ? 16 : 14
                return "#0x" + hexZeroPadded(value, digits: digits)
            }
            return "#\(value)"
        case let .immediate(value, _):
            return "#\(value)"
        case let .conditionCode(cc):
            return conditionText(cc)
        case let .memory(mem):
            return memoryText(mem)
        case let .shiftAmount(kind, amount):
            return "\(shiftKindName(kind)) #\(amount)"
        case let .shiftedRegister(reg, kind, amount):
            if kind == .lsl, amount == 0 {
                return reg.name
            }
            return "\(reg.name), \(shiftKindName(kind)) #\(amount)"
        case let .extendedRegister(reg, extend, shift):
            if shift == 0 {
                return "\(reg.name), \(extendKindName(extend))"
            }
            return "\(reg.name), \(extendKindName(extend)) #\(shift)"
        default:
            return "?unsupported-operand"
        }
    }

    @_effects(readonly)
    private static func vectorRegisterText(_ vr: VectorRegisterRef) -> String {
        switch vr.view {
        case let .full(arrangement):
            "v\(vr.registerIndex).\(arrangementSuffix(arrangement))"
        case let .scalar(size):
            "\(scalarPrefix(size))\(vr.registerIndex)"
        case let .element(arrangement, index):
            "v\(vr.registerIndex).\(scalarSuffix(arrangement.elementSize))[\(index)]"
        case let .elementGroup(elementSize, count, index):
            "v\(vr.registerIndex).\(count)\(scalarSuffix(elementSize))[\(index)]"
        case let .lane(index):
            "v\(vr.registerIndex)[\(index)]"
        }
    }

    @_effects(readonly)
    private static func memoryText(_ mem: MemoryOperand) -> String {
        // PC-base literal loads (SIMD LDR (literal)) render as
        // `#<displacement>` with no brackets, matching llvm-mc and the
        // integer LSCanonicalizer.
        let baseText: String
        switch mem.base {
        case .pc:
            return "#\(mem.displacement)"
        case let .register(r):
            baseText = r.name
        }
        let disp = mem.displacement
        switch mem.writeback {
        case .preIndex:
            return "[\(baseText), #\(disp)]!"
        case .postIndex:
            if let idx = mem.index {
                return "[\(baseText)], \(idx.name)"
            }
            return "[\(baseText)], #\(disp)"
        case .none:
            if let idx = mem.index {
                let extPart = mem.extend == .none
                    ? ""
                    : ", \(extendKindName(mem.extend))\(mem.shift == 0xFF ? "" : " #\(mem.shift)")"
                return "[\(baseText), \(idx.name)\(extPart)]"
            }
            if disp != 0 {
                return "[\(baseText), #\(disp)]"
            }
            return "[\(baseText)]"
        }
    }

    private static func floatImmediateText(bits: UInt64, kind: FloatImmediateKind) -> String {
        // FCMP/FCMPE compare-with-zero encodes a fixed `#0.0` (bits == 0);
        // FMOV-immediate never encodes zero. Non-zero values render as
        // llvm-mc does — signed fixed 8-fraction-digit decimal
        // (`#1.50000000`, `#-13.00000000`).
        if bits == 0 { return "#0.0" }
        let value = switch kind {
        case .half: halfBitsToDouble(UInt16(truncatingIfNeeded: bits))
        case .single: Double(Float(bitPattern: UInt32(truncatingIfNeeded: bits)))
        case .double: Double(bitPattern: bits)
        }
        return "#" + fixedEightFractionText(value)
    }

    /// IEEE 754 binary16 → binary64 by pure bit manipulation — the
    /// stdlib-only equivalent of `Double(Float16(bitPattern:))`, proven
    /// byte-identical over all 2^16 half patterns (subnormals, ±0, ±inf,
    /// NaN payload + quiet-bit behavior) by the format-parity tests.
    /// Replaces `Float16`, whose platform availability would otherwise
    /// set the package's deployment floors and exclude Intel macOS.
    private static func halfBitsToDouble(_ halfBits: UInt16) -> Double {
        let sign = UInt64(halfBits >> 15) << 63
        let exponent = Int((halfBits >> 10) & 0x1F)
        let mantissa = UInt64(halfBits & 0x3FF)
        if exponent == 0 {
            if mantissa == 0 { return Double(bitPattern: sign) } // ±0
            // Subnormal: value = mantissa × 2^-24. Normalize into the
            // double's implicit-leading-1 form.
            var m = mantissa
            var e = 1
            while m & 0x400 == 0 {
                m <<= 1
                e -= 1
            }
            let doubleExponent = UInt64(e - 15 + 1023)
            return Double(bitPattern: sign | (doubleExponent << 52) | ((m & 0x3FF) << 42))
        }
        if exponent == 0x1F {
            if mantissa == 0 { return Double(bitPattern: sign | 0x7FF0_0000_0000_0000) } // ±inf
            // NaN: payload shifts to the double's high mantissa bits;
            // the quiet bit is forced, matching the conversion's
            // quieting of signaling NaNs (payload preserved).
            let payload = (mantissa << 42) | 0x0008_0000_0000_0000
            return Double(bitPattern: sign | 0x7FF0_0000_0000_0000 | payload)
        }
        let doubleExponent = UInt64(exponent - 15 + 1023)
        return Double(bitPattern: sign | (doubleExponent << 52) | (mantissa << 42))
    }

    /// Lowercase hex, zero-padded to `digits` — the pure-Swift
    /// equivalent of C `"%0<digits>llx"`.
    private static func hexZeroPadded(_ value: UInt64, digits: Int) -> String {
        let hex = String(value, radix: 16)
        if hex.count >= digits { return hex }
        return String(repeating: "0", count: digits - hex.count) + hex
    }

    /// Fixed 8-fraction-digit decimal rendering of `value` — the
    /// pure-Swift equivalent of C `"%.8f"`: the exact binary value,
    /// rounded half-to-even at the 8th fraction digit. Negative finite
    /// values (including -0.0) keep their sign; infinities render
    /// `inf`/`-inf`; NaNs render unsigned `nan` — all matching Darwin
    /// libc, verified exhaustively by the format-parity tests.
    private static func fixedEightFractionText(_ value: Double) -> String {
        let bits = value.bitPattern
        let negative = (bits >> 63) != 0
        let biasedExponent = Int((bits >> 52) & 0x7FF)
        let fraction = bits & 0x000F_FFFF_FFFF_FFFF
        if biasedExponent == 0x7FF {
            if fraction != 0 { return "nan" }
            return negative ? "-inf" : "inf"
        }
        // Magnitude = significand × 2^exponent with significand < 2^53.
        let significand = biasedExponent == 0 ? fraction : fraction | (1 << 52)
        let exponent = (biasedExponent == 0 ? 1 : biasedExponent) - 1075
        let sign = negative ? "-" : ""
        if exponent >= 0 {
            return sign + decimalTextShiftedLeft(significand, by: exponent) + ".00000000"
        }
        // Magnitude × 10^8 = (significand × 5^8) / 2^(-exponent - 8):
        // a < 2^72 numerator over a power of two.
        let numerator = significand.multipliedFullWidth(by: 390_625)
        var high = numerator.high
        var low = numerator.low
        let denominatorShift = -exponent - 8
        if denominatorShift <= 0 {
            // exponent ∈ -8...-1: the power of two scales the numerator
            // up instead (by 0...7 bits) — exact, no rounding. Swift's
            // smart shift makes `low >> 64` zero when the up-shift is 0.
            let up = -denominatorShift
            high = (high << up) | (low >> (64 - up))
            low = low << up
        } else {
            (high, low) = shiftRightRoundingHalfToEven(high: high, low: low, by: denominatorShift)
        }
        return sign + fractionPointInserted(decimalText(high: high, low: low))
    }

    /// `high:low >> shift` (`shift >= 1`) with round-half-to-even on
    /// the dropped remainder.
    private static func shiftRightRoundingHalfToEven(
        high: UInt64, low: UInt64, by shift: Int,
    ) -> (high: UInt64, low: UInt64) {
        var quotientHigh: UInt64
        var quotientLow: UInt64
        let remainderHigh: UInt64
        let remainderLow: UInt64
        if shift < 64 {
            quotientHigh = high >> shift
            quotientLow = (low >> shift) | (high << (64 - shift))
            remainderHigh = 0
            remainderLow = low & ((1 << shift) &- 1)
        } else if shift < 128 {
            quotientHigh = 0
            quotientLow = high >> (shift - 64)
            remainderHigh = shift == 64 ? 0 : high & ((1 << (shift - 64)) &- 1)
            remainderLow = low
        } else {
            quotientHigh = 0
            quotientLow = 0
            remainderHigh = high
            remainderLow = low
        }
        let roundsUp: Bool
        if shift >= 129 {
            // half = 2^(shift-1) exceeds 128 bits; no remainder reaches it.
            roundsUp = false
        } else {
            let halfHigh: UInt64 = shift > 64 ? 1 << (shift - 65) : 0
            let halfLow: UInt64 = shift > 64 ? 0 : 1 << (shift - 1)
            if remainderHigh == halfHigh, remainderLow == halfLow {
                roundsUp = (quotientLow & 1) == 1
            } else if remainderHigh != halfHigh {
                roundsUp = remainderHigh > halfHigh
            } else {
                roundsUp = remainderLow > halfLow
            }
        }
        if roundsUp {
            // The increment cannot wrap the low word: the only caller
            // divides significand × 5^8 < 2^72 by 2^shift, and no IEEE-754
            // double yields a quotient whose low 64 bits are all-ones
            // (exhaustively: shift ≤ 8 from the 2^72 bound, and none of
            // the candidate windows contains a multiple of 5^8).
            quotientLow &+= 1
        }
        return (quotientHigh, quotientLow)
    }

    /// Decimal digits of the 128-bit value `high:low`.
    private static func decimalText(high: UInt64, low: UInt64) -> String {
        if high == 0 { return String(low) }
        var hi = high
        var lo = low
        var groups: [UInt64] = []
        groups.reserveCapacity(3)
        while hi != 0 {
            // 128-by-64 long division by 10^9, one base-10^9 group per pass.
            let headQuotient = hi / 1_000_000_000
            let headRemainder = hi % 1_000_000_000
            let (tailQuotient, group) = UInt64(1_000_000_000)
                .dividingFullWidth((high: headRemainder, low: lo))
            hi = headQuotient
            lo = tailQuotient
            groups.append(group)
        }
        var text = String(lo)
        for group in groups.reversed() {
            text += zeroPaddedNine(group)
        }
        return text
    }

    /// Decimal digits of `value × 2^shift`, arbitrary precision over
    /// base-10^9 limbs (a double's integer part spans up to 309 digits).
    private static func decimalTextShiftedLeft(_ value: UInt64, by shift: Int) -> String {
        var limbs: [UInt64] = []
        limbs.reserveCapacity(1 &+ (shift &+ 83) / 29)
        var seed = value
        repeat {
            limbs.append(seed % 1_000_000_000)
            seed /= 1_000_000_000
        } while seed != 0
        var remaining = shift
        while remaining > 0 {
            // A limb (< 2^30) shifted 29 bits plus a carry (≤ 2^29)
            // stays below 2^60: no per-limb overflow.
            let step = min(remaining, 29)
            var carry: UInt64 = 0
            for i in limbs.indices {
                let product = (limbs[i] << step) &+ carry
                limbs[i] = product % 1_000_000_000
                carry = product / 1_000_000_000
            }
            while carry != 0 {
                limbs.append(carry % 1_000_000_000)
                carry /= 1_000_000_000
            }
            remaining -= step
        }
        var text = String(limbs[limbs.count - 1])
        for i in stride(from: limbs.count - 2, through: 0, by: -1) {
            text += zeroPaddedNine(limbs[i])
        }
        return text
    }

    private static func zeroPaddedNine(_ group: UInt64) -> String {
        let digits = String(group)
        if digits.count >= 9 { return digits }
        return String(repeating: "0", count: 9 - digits.count) + digits
    }

    /// Insert the decimal point 8 digits from the right, zero-filling
    /// the integer part when the value has fewer than 9 digits.
    private static func fractionPointInserted(_ digits: String) -> String {
        if digits.count <= 8 {
            return "0." + String(repeating: "0", count: 8 - digits.count) + digits
        }
        let pointIndex = digits.index(digits.endIndex, offsetBy: -8)
        return String(digits[..<pointIndex]) + "." + String(digits[pointIndex...])
    }

    @_effects(readonly)
    private static func arrangementSuffix(_ a: VectorArrangement) -> String {
        switch a {
        case .b8: "8b"
        case .b16: "16b"
        case .h4: "4h"
        case .h8: "8h"
        case .s2: "2s"
        case .s4: "4s"
        case .d1: "1d"
        case .d2: "2d"
        case .q1: "1q"
        case .h2: "2h"
        }
    }

    @_effects(readonly)
    private static func scalarPrefix(_ s: ScalarSize) -> String {
        switch s {
        case .b: "b"
        case .h: "h"
        case .s: "s"
        case .d: "d"
        case .q: "q"
        }
    }

    @_effects(readonly)
    private static func scalarSuffix(_ s: ScalarSize) -> String {
        // Element-view operands use .b/.h/.s/.d only — .q never reaches
        // here (element-indexed operand format excludes Q-form). The
        // default arm absorbs the unreachable .q case.
        switch s {
        case .b: "b"
        case .h: "h"
        case .s: "s"
        default: "d" // .d (or .q sentinel — unreachable).
        }
    }

    @_effects(readonly)
    private static func conditionText(_ cc: ConditionCode) -> String {
        switch cc {
        case .eq: "eq"
        case .ne: "ne"
        case .cs: "hs"
        case .cc: "lo"
        case .mi: "mi"
        case .pl: "pl"
        case .vs: "vs"
        case .vc: "vc"
        case .hi: "hi"
        case .ls: "ls"
        case .ge: "ge"
        case .lt: "lt"
        case .gt: "gt"
        case .le: "le"
        case .al: "al"
        case .nv: "nv"
        }
    }

    @_effects(readonly)
    private static func shiftKindName(_ s: ShiftKind) -> String {
        switch s {
        case .lsl: "lsl"
        case .lsr: "lsr"
        case .asr: "asr"
        case .ror: "ror"
        case .msl: "msl"
        }
    }

    @_effects(readonly)
    private static func extendKindName(_ e: ExtendKind) -> String {
        switch e {
        case .none: ""
        case .uxtb: "uxtb"
        case .uxth: "uxth"
        case .uxtw: "uxtw"
        case .uxtx: "uxtx"
        case .sxtb: "sxtb"
        case .sxth: "sxth"
        case .sxtw: "sxtw"
        case .sxtx: "sxtx"
        case .lsl: "lsl"
        }
    }
}
