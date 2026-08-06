// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// What an address-forming instruction points at, resolved through the
/// binary's data sections and symbols.
@frozen
public struct ReferencedData: Sendable, Equatable {
    /// The resolved C string at the target (already unescaped source bytes;
    /// the renderer escapes and truncates for display), present only when the
    /// target lands in a cstring-literal section.
    public let string: String?
    /// The data symbol the target resolves to.
    public let symbol: String?
    /// The containing section's display name (`__TEXT,__cstring`,
    /// `__DATA_CONST,__const`).
    public let section: String

    @inlinable
    public init(string: String?, symbol: String?, section: String) {
        self.string = string
        self.symbol = symbol
        self.section = section
    }
}

/// The printable-character hint for an immediate that falls in the ASCII
/// range.
public enum CharLiteralHint {
    /// The comparison and bit-test mnemonics whose immediate is plausibly a
    /// character.
    static func isCandidate(_ mnemonic: Mnemonic) -> Bool {
        switch mnemonic {
        case .cmp, .cmn, .ccmp, .ccmn, .tst:
            true
        default:
            false
        }
    }

    /// The printable ASCII character one of `instruction`'s immediates names,
    /// or `nil`.
    public static func character(for instruction: Instruction) -> Character? {
        guard isCandidate(instruction.mnemonic), !touchesStackPointer(instruction) else { return nil }
        for operand in instruction.operands {
            let value: UInt64? = switch operand {
            case let .immediate(immediate, _):
                immediate >= 0 ? UInt64(immediate) : nil
            case let .unsignedImmediate(immediate, _):
                immediate
            default:
                nil
            }
            if let value, (0x20 ... 0x7E).contains(value) {
                return Character(UnicodeScalar(UInt8(value)))
            }
        }
        return nil
    }

    /// Whether any register operand of `instruction` is the stack pointer
    /// (`sp` / `wsp`), the marker of frame arithmetic the character hint must
    /// not annotate.
    static func touchesStackPointer(_ instruction: Instruction) -> Bool {
        for operand in instruction.operands {
            switch operand {
            case let .register(reg) where reg.isStackPointer:
                return true
            case let .shiftedRegister(reg, _, _) where reg.isStackPointer:
                return true
            case let .extendedRegister(reg, _, _) where reg.isStackPointer:
                return true
            default:
                continue
            }
        }
        return false
    }
}

/// Resolves an address-forming instruction's PC-relative target to a
/// ``ReferencedData``.
@frozen
public struct ReferencedDataResolver: Sendable {
    /// Non-code, file-backed sections, for section attribution and string
    /// reads.
    public let dataSections: [DataSection]
    /// Defined symbols, address-indexed (for the data-symbol tier).
    public let symbols: SymbolIndex

    @inlinable
    public init(dataSections: [DataSection], symbols: SymbolIndex) {
        self.dataSections = dataSections
        self.symbols = symbols
    }

    /// The empty resolver (a binary with no data sections, or the
    /// direct-decode modes), which resolves nothing.
    public static let empty = ReferencedDataResolver(dataSections: [], symbols: .empty)

    /// The absolute data address `instruction` forms, covering both a single
    /// self-contained PC-relative instruction and the `adrp` + offset idiom
    /// completed by `preceding`.
    public func targetAddress(of instruction: Instruction, preceding: Instruction?) -> UInt64? {
        if let preceding, preceding.mnemonic == .adrp,
           let page = preceding.pcRelativeTarget,
           let pageRegister = adrpDestination(preceding),
           let offset = lowOffsetCompleting(instruction, page: pageRegister)
        {
            return page &+ offset
        }
        if instruction.mnemonic != .adrp {
            return instruction.pcRelativeTarget
        }
        return nil
    }

    /// Resolve `instruction` (with the instruction before it) to a referenced
    /// datum, or `nil` when it forms no in-section data address.
    public func resolve(_ instruction: Instruction, preceding: Instruction?) -> ReferencedData? {
        guard let target = targetAddress(of: instruction, preceding: preceding) else { return nil }
        return resolve(target: target)
    }

    /// Resolve a bare absolute target address to its section, string, and data
    /// symbol.
    public func resolve(target: UInt64) -> ReferencedData? {
        guard let section = dataSections.first(where: { $0.containsAddress(target) }) else { return nil }
        let string = section.isCStringLiteral ? section.cString(at: target) : nil
        return ReferencedData(string: string, symbol: dataSymbol(at: target), section: section.displayName)
    }

    /// The destination register of an `adrp xD, <page>`.
    func adrpDestination(_ adrp: Instruction) -> UInt8? {
        for operand in adrp.operands {
            if case let .register(reg) = operand { return reg.canonicalIndex }
        }
        return nil
    }

    /// The low byte-offset `instruction` adds to a page base held in `page`,
    /// or `nil` when it is not the completing half.
    func lowOffsetCompleting(_ instruction: Instruction, page: UInt8) -> UInt64? {
        switch instruction.mnemonic {
        case .add:
            addImmediateOffset(instruction, base: page)
        case .ldr, .ldrsw:
            loadDisplacementOffset(instruction, base: page)
        default:
            nil
        }
    }

    /// For `add xD, xS, #imm` with `xS == base`.
    func addImmediateOffset(_ instruction: Instruction, base: UInt8) -> UInt64? {
        guard instruction.operands.count == 3,
              case let .register(source) = instruction.operands[1],
              source.canonicalIndex == base
        else { return nil }
        switch instruction.operands[2] {
        case let .immediate(value, _):
            return value >= 0 ? UInt64(value) : nil
        case let .unsignedImmediate(value, _):
            return value
        default:
            return nil
        }
    }

    /// For `ldr xD, [xS, #imm]` (or `ldrsw`) with base `xS == base`.
    func loadDisplacementOffset(_ instruction: Instruction, base: UInt8) -> UInt64? {
        guard let memory = memoryOperand(instruction),
              case let .register(reg) = memory.base,
              reg.canonicalIndex == base,
              memory.index == nil,
              memory.writeback == .none,
              memory.displacement >= 0
        else { return nil }
        return UInt64(memory.displacement)
    }

    /// The single memory operand of a load, or `nil` if it has none.
    func memoryOperand(_ instruction: Instruction) -> MemoryOperand? {
        for operand in instruction.operands {
            if case let .memory(memory) = operand { return memory }
        }
        return nil
    }

    /// The data symbol at `target`.
    func dataSymbol(at target: UInt64) -> String? {
        if let exact = symbols.name(at: target) {
            return exact
        }
        guard let nearest = symbols.nearest(atOrBefore: target) else { return nil }
        let sameSection = dataSections.contains { section in
            section.containsAddress(target) && section.containsAddress(nearest.address)
        }
        guard sameSection else { return nil }
        return nearest.name + "+0x" + String(target &- nearest.address, radix: 16)
    }
}
