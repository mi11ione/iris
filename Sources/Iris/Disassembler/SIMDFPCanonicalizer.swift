// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum SIMDFPCanonicalizer {
    /// The byte path.
    @_optimize(speed)
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        if instruction.mnemonic == .undefined { return }
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) {
            CryptoAppleExtensionsCanonicalizer.format(instruction, into: &out)
            return
        }
        let ops = instruction.operands
        let listSize = vectorListSize(mnemonic: instruction.mnemonic, operandCount: ops.count)
        let listIsLeading = listGroupingIsLeading(mnemonic: instruction.mnemonic)
        putMnemonic(instruction.mnemonic, into: &out)
        if ops.isEmpty { return }
        out.put(UInt8(ascii: " "))
        var index = 0
        var first = true
        if listIsLeading, listSize > 0 {
            putVectorList(ops, start: 0, count: listSize, into: &out)
            index = listSize
            first = false
        }
        while index < ops.count {
            if !first { out.put(", ") }
            first = false
            if !listIsLeading, listSize > 0, index == 1 {
                putVectorList(ops, start: 1, count: listSize, into: &out)
                index += listSize
                continue
            }
            putOperand(ops[index], into: &out)
            index += 1
        }
    }

    /// Number of leading `.vectorRegister` operands that should be rendered as
    /// a single curly-brace list.
    @_effects(readonly)
    private static func vectorListSize(
        mnemonic: Mnemonic, operandCount: Int,
    ) -> Int {
        switch mnemonic {
        case .ld1, .st1, .ld2, .st2, .ld3, .st3, .ld4, .st4, .ldap1, .stl1:
            max(0, operandCount - 1)
        case .ld1r, .ld2r, .ld3r, .ld4r:
            max(0, operandCount - 1)
        case .tbl, .tbx, .luti2, .luti4:
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

    private static func putVectorList(
        _ operands: Instruction.Operands, start: Int, count: Int, into out: inout TextBytes,
    ) {
        var trailingIndex: UInt8?
        out.put("{ ")
        for i in 0 ..< count {
            if i > 0 { out.put(", ") }
            let op = operands[start + i]
            if case let .vectorRegister(vr) = op, case let .element(arrangement, idx) = vr.view {
                out.put(UInt8(ascii: "v"))
                out.putDecimal(UInt64(vr.registerIndex))
                out.put(UInt8(ascii: "."))
                putScalarSuffix(arrangement.elementSize, into: &out)
                trailingIndex = idx
            } else {
                putOperand(op, into: &out)
            }
        }
        out.put(" }")
        if let trailingIndex {
            out.put(UInt8(ascii: "["))
            out.putDecimal(UInt64(trailingIndex))
            out.put(UInt8(ascii: "]"))
        }
    }

    private static func putOperand(_ op: Operand, into out: inout TextBytes) {
        switch op {
        case let .vectorRegister(vr):
            putVectorRegister(vr, into: &out)
        case let .register(r):
            RegisterNames.put(r, into: &out)
        case let .floatImmediate(bits, kind):
            out.putString(floatImmediateText(bits: bits, kind: kind))
        case let .unsignedImmediate(value, width):
            if width == 64 {
                if value == 0 {
                    out.put("#0000000000000000")
                    return
                }
                let digits = (value >> 56) != 0 ? 16 : 14
                out.put("#0x")
                out.putString(hexZeroPadded(value, digits: digits))
                return
            }
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        case let .immediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        case let .conditionCode(cc):
            putConditionText(cc, into: &out)
        case let .memory(mem):
            putMemory(mem, into: &out)
        case let .shiftAmount(kind, amount):
            putShiftKindName(kind, into: &out)
            out.put(" #")
            out.putDecimal(UInt64(amount))
        case let .shiftedRegister(reg, kind, amount):
            RegisterNames.put(reg, into: &out)
            if kind == .lsl, amount == 0 { return }
            out.put(", ")
            putShiftKindName(kind, into: &out)
            out.put(" #")
            out.putDecimal(UInt64(amount))
        case let .extendedRegister(reg, extend, shift):
            RegisterNames.put(reg, into: &out)
            out.put(", ")
            putExtendKindName(extend, into: &out)
            if shift != 0 {
                out.put(" #")
                out.putDecimal(UInt64(shift))
            }
        default:
            out.put("?unsupported-operand")
        }
    }

    private static func putVectorRegister(_ vr: VectorRegisterRef, into out: inout TextBytes) {
        let n = UInt64(vr.registerIndex)
        switch vr.view {
        case let .full(arrangement):
            out.put(UInt8(ascii: "v"))
            out.putDecimal(n)
            out.put(UInt8(ascii: "."))
            putArrangementSuffix(arrangement, into: &out)
        case let .scalar(size):
            putScalarPrefix(size, into: &out)
            out.putDecimal(n)
        case let .element(arrangement, index):
            out.put(UInt8(ascii: "v"))
            out.putDecimal(n)
            out.put(UInt8(ascii: "."))
            putScalarSuffix(arrangement.elementSize, into: &out)
            out.put(UInt8(ascii: "["))
            out.putDecimal(UInt64(index))
            out.put(UInt8(ascii: "]"))
        case let .elementGroup(elementSize, count, index):
            out.put(UInt8(ascii: "v"))
            out.putDecimal(n)
            out.put(UInt8(ascii: "."))
            out.putDecimal(UInt64(count))
            putScalarSuffix(elementSize, into: &out)
            out.put(UInt8(ascii: "["))
            out.putDecimal(UInt64(index))
            out.put(UInt8(ascii: "]"))
        case let .lane(index):
            out.put(UInt8(ascii: "v"))
            out.putDecimal(n)
            out.put(UInt8(ascii: "["))
            out.putDecimal(UInt64(index))
            out.put(UInt8(ascii: "]"))
        }
    }

    private static func putMemory(_ mem: MemoryOperand, into out: inout TextBytes) {
        let baseReg: RegisterRef
        switch mem.base {
        case .pc:
            out.put(UInt8(ascii: "#"))
            out.putDecimal(mem.displacement)
            return
        case let .register(r):
            baseReg = r
        }
        let disp = mem.displacement
        out.put(UInt8(ascii: "["))
        RegisterNames.put(baseReg, into: &out)
        switch mem.writeback {
        case .preIndex:
            out.put(", #")
            out.putDecimal(disp)
            out.put("]!")
        case .postIndex:
            if let idx = mem.index {
                out.put("], ")
                RegisterNames.put(idx, into: &out)
                return
            }
            out.put("], #")
            out.putDecimal(disp)
        case .none:
            if let idx = mem.index {
                out.put(", ")
                RegisterNames.put(idx, into: &out)
                if mem.extend != .none {
                    out.put(", ")
                    putExtendKindName(mem.extend, into: &out)
                    if mem.shift != 0xFF {
                        out.put(" #")
                        out.putDecimal(UInt64(mem.shift))
                    }
                }
                out.put(UInt8(ascii: "]"))
                return
            }
            if disp != 0 {
                out.put(", #")
                out.putDecimal(disp)
            }
            out.put(UInt8(ascii: "]"))
        }
    }

    private static func floatImmediateText(bits: UInt64, kind: FloatImmediateKind) -> String {
        if bits == 0 { return "#0.0" }
        let value = switch kind {
        case .half: halfBitsToDouble(UInt16(truncatingIfNeeded: bits))
        case .single: Double(Float(bitPattern: UInt32(truncatingIfNeeded: bits)))
        case .double: Double(bitPattern: bits)
        }
        return "#" + fixedEightFractionText(value)
    }

    /// IEEE 754 binary16 → binary64 by pure bit manipulation, the stdlib-only
    /// equivalent of `Double(Float16(bitPattern:))`, proven byte-identical
    /// over all 2^16 half patterns by the format-parity tests.
    static func halfBitsToDouble(_ halfBits: UInt16) -> Double {
        let sign = UInt64(halfBits >> 15) << 63
        let exponent = Int((halfBits >> 10) & 0x1F)
        let mantissa = UInt64(halfBits & 0x3FF)
        if exponent == 0 {
            if mantissa == 0 { return Double(bitPattern: sign) }
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
            if mantissa == 0 { return Double(bitPattern: sign | 0x7FF0_0000_0000_0000) }
            let payload = (mantissa << 42) | 0x0008_0000_0000_0000
            return Double(bitPattern: sign | 0x7FF0_0000_0000_0000 | payload)
        }
        let doubleExponent = UInt64(exponent - 15 + 1023)
        return Double(bitPattern: sign | (doubleExponent << 52) | (mantissa << 42))
    }

    /// Lowercase hex, zero-padded to `digits`.
    private static func hexZeroPadded(_ value: UInt64, digits: Int) -> String {
        let hex = String(value, radix: 16)
        if hex.count >= digits { return hex }
        return String(repeating: "0", count: digits - hex.count) + hex
    }

    /// Fixed 8-fraction-digit decimal rendering of `value`, the pure-Swift
    /// equivalent of C `"%.8f"`.
    static func fixedEightFractionText(_ value: Double) -> String {
        let bits = value.bitPattern
        let negative = (bits >> 63) != 0
        let biasedExponent = Int((bits >> 52) & 0x7FF)
        let fraction = bits & 0x000F_FFFF_FFFF_FFFF
        if biasedExponent == 0x7FF {
            if fraction != 0 { return "nan" }
            return negative ? "-inf" : "inf"
        }
        let significand = biasedExponent == 0 ? fraction : fraction | (1 << 52)
        let exponent = (biasedExponent == 0 ? 1 : biasedExponent) - 1075
        let sign = negative ? "-" : ""
        if exponent >= 0 {
            return sign + decimalTextShiftedLeft(significand, by: exponent) + ".00000000"
        }
        let numerator = significand.multipliedFullWidth(by: 390_625)
        var high = numerator.high
        var low = numerator.low
        let denominatorShift = -exponent - 8
        if denominatorShift <= 0 {
            let up = -denominatorShift
            high = (high << up) | (low >> (64 - up))
            low = low << up
        } else {
            (high, low) = shiftRightRoundingHalfToEven(high: high, low: low, by: denominatorShift)
        }
        return sign + fractionPointInserted(decimalText(high: high, low: low))
    }

    /// `high:low >> shift` (`shift >= 1`) with round-half-to-even on the
    /// dropped remainder.
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

    /// Decimal digits of `value × 2^shift`, arbitrary precision over base-10^9
    /// limbs (a double's integer part spans up to 309 digits).
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

    /// Insert the decimal point 8 digits from the right, zero-filling the
    /// integer part when the value has fewer than 9 digits.
    private static func fractionPointInserted(_ digits: String) -> String {
        if digits.count <= 8 {
            return "0." + String(repeating: "0", count: 8 - digits.count) + digits
        }
        let pointIndex = digits.index(digits.endIndex, offsetBy: -8)
        return String(digits[..<pointIndex]) + "." + String(digits[pointIndex...])
    }

    @inline(__always)
    private static func putArrangementSuffix(_ a: VectorArrangement, into out: inout TextBytes) {
        switch a {
        case .b8: out.put("8b")
        case .b16: out.put("16b")
        case .h4: out.put("4h")
        case .h8: out.put("8h")
        case .s2: out.put("2s")
        case .s4: out.put("4s")
        case .d1: out.put("1d")
        case .d2: out.put("2d")
        case .q1: out.put("1q")
        case .h2: out.put("2h")
        }
    }

    @inline(__always)
    private static func putScalarPrefix(_ s: ScalarSize, into out: inout TextBytes) {
        switch s {
        case .b: out.put("b")
        case .h: out.put("h")
        case .s: out.put("s")
        case .d: out.put("d")
        case .q: out.put("q")
        }
    }

    @inline(__always)
    private static func putScalarSuffix(_ s: ScalarSize, into out: inout TextBytes) {
        switch s {
        case .b: out.put("b")
        case .h: out.put("h")
        case .s: out.put("s")
        default: out.put("d")
        }
    }

    @inline(__always)
    private static func putConditionText(_ cc: ConditionCode, into out: inout TextBytes) {
        switch cc {
        case .eq: out.put("eq")
        case .ne: out.put("ne")
        case .cs: out.put("hs")
        case .cc: out.put("lo")
        case .mi: out.put("mi")
        case .pl: out.put("pl")
        case .vs: out.put("vs")
        case .vc: out.put("vc")
        case .hi: out.put("hi")
        case .ls: out.put("ls")
        case .ge: out.put("ge")
        case .lt: out.put("lt")
        case .gt: out.put("gt")
        case .le: out.put("le")
        case .al: out.put("al")
        case .nv: out.put("nv")
        }
    }

    @inline(__always)
    private static func putShiftKindName(_ s: ShiftKind, into out: inout TextBytes) {
        switch s {
        case .lsl: out.put("lsl")
        case .lsr: out.put("lsr")
        case .asr: out.put("asr")
        case .ror: out.put("ror")
        case .msl: out.put("msl")
        }
    }

    @inline(__always)
    private static func putExtendKindName(_ e: ExtendKind, into out: inout TextBytes) {
        switch e {
        case .none: break
        case .uxtb: out.put("uxtb")
        case .uxth: out.put("uxth")
        case .uxtw: out.put("uxtw")
        case .uxtx: out.put("uxtx")
        case .sxtb: out.put("sxtb")
        case .sxth: out.put("sxth")
        case .sxtw: out.put("sxtw")
        case .sxtx: out.put("sxtx")
        case .lsl: out.put("lsl")
        }
    }
}
