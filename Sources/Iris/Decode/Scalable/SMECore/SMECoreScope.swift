// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Whether `encoding` is an SME-core instruction owned by SME-core —
/// streaming-mode outer products, ZA tile/array load-store, MOVA, ZERO, and
/// horizontal/vertical accumulate. The complement inside the SME region
/// (SME2 multi-vector, ZT0, LUTI) is SME2's.
@inline(__always)
@_effects(readonly)
public func isSMECoreEncoding(_ encoding: UInt32) -> Bool {
    guard isSMEEncoding(encoding) else { return false }
    let bit24 = encoding & 0x0100_0000 != 0
    let bit23 = encoding & 0x0080_0000 != 0
    switch encoding & 0xE000_0000 {
    case 0x8000_0000:
        guard bit23 else { return false }
        return bit24 ? true : smeIsCoreOuterProduct(encoding)
    case 0xA000_0000:
        guard bit23 else { return false }
        return smeIsCoreOuterProduct(encoding)
    case 0xC000_0000:
        guard !bit24 else { return false }
        return smeIsCoreMoveZero(encoding)
    default:
        if bit24, !bit23 { return !smeIsZT0FillSpill(encoding) }
        return true
    }
}

/// Whether `encoding` is an SME-core outer-product encoding in the cells
/// needing a row-by-row claim; the residue words (2-way integer MOPA at
/// bit3=1, F8 sources, MOP4) match none.
@inline(__always)
@_effects(readonly)
func smeIsCoreOuterProduct(_ e: UInt32) -> Bool {
    switch e & 0xFFE0_001C {
    case 0x8080_0000, 0x8080_0010, 0x8080_0008, 0x8080_0018,
         0x8180_0000, 0x8180_0010,
         0x81A0_0000, 0x81A0_0010,
         0xA080_0000, 0xA080_0010, 0xA0A0_0000, 0xA0A0_0010,
         0xA180_0000, 0xA180_0010, 0xA1A0_0000, 0xA1A0_0010:
        return true
    default:
        break
    }
    switch e & 0xFFE0_0018 {
    case 0x80C0_0000, 0x80C0_0010,
         0xA0C0_0000, 0xA0C0_0010, 0xA0E0_0000, 0xA0E0_0010,
         0xA1C0_0000, 0xA1C0_0010, 0xA1E0_0000, 0xA1E0_0010:
        return true
    default:
        return false
    }
}

/// Whether `encoding` matches a SME-core core MOVA (insert or extract), ZERO,
/// or ADDHA/ADDVA block.
@inline(__always)
@_effects(readonly)
func smeIsCoreMoveZero(_ e: UInt32) -> Bool {
    switch e & 0xFFFF_0010 {
    case 0xC000_0000, 0xC040_0000, 0xC080_0000, 0xC0C0_0000, 0xC0C1_0000:
        return true
    default:
        break
    }
    switch e & 0xFFFF_0200 {
    case 0xC002_0000, 0xC042_0000, 0xC082_0000, 0xC0C2_0000, 0xC0C3_0000:
        return true
    default:
        break
    }
    if e & 0xFFFF_FF00 == 0xC008_0000 { return true }
    let addS = e & 0xFFFF_001C
    if addS == 0xC090_0000 || addS == 0xC091_0000 { return true }
    let addD = e & 0xFFFF_0018
    if addD == 0xC0D0_0000 || addD == 0xC0D1_0000 { return true }
    return false
}

/// Whether `encoding` is an SME2 `ZT0` fill (`LDR ZT0`) or spill (`STR ZT0`).
@inline(__always)
@_effects(readonly)
func smeIsZT0FillSpill(_ e: UInt32) -> Bool {
    e & 0xFFFF_FC1F == 0xE11F_8000 || e & 0xFFFF_FC1F == 0xE13F_8000
}
