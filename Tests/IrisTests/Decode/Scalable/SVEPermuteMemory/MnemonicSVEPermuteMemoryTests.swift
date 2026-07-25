// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the 2s.5 mnemonic slab — the SVE / SVE2 permute, memory, and
/// crypto tokens. Their raw values continue the SVE slab from 16684 (2s.4 ended
/// at 16683) as a contiguous, collision-free run: a downstream consumer keys off
/// these integers, so a renumbering or a gap would silently re-interpret every
/// record. Shared tokens (ldr/str/rev/sel/tbl/zip1/aese/pmull/luti2…) are reused
/// from earlier slabs and are validated where they decode, not here.
@Suite("SVE permute/memory/crypto / mnemonic slab")
struct MnemonicSVEPermuteMemoryTests {
    /// Every token 2s.5 introduces, in encoding order, with its pinned raw value.
    private static let slab: [(Mnemonic, UInt16, String)] = [
        (.ld1b, 16684, "ld1b"), (.ld1h, 16685, "ld1h"), (.ld1w, 16686, "ld1w"), (.ld1d, 16687, "ld1d"),
        (.ld1sb, 16688, "ld1sb"), (.ld1sh, 16689, "ld1sh"), (.ld1sw, 16690, "ld1sw"), (.ld1q, 16691, "ld1q"),
        (.st1b, 16692, "st1b"), (.st1h, 16693, "st1h"), (.st1w, 16694, "st1w"), (.st1d, 16695, "st1d"), (.st1q, 16696, "st1q"),
        (.ldff1b, 16697, "ldff1b"), (.ldff1h, 16698, "ldff1h"), (.ldff1w, 16699, "ldff1w"), (.ldff1d, 16700, "ldff1d"),
        (.ldff1sb, 16701, "ldff1sb"), (.ldff1sh, 16702, "ldff1sh"), (.ldff1sw, 16703, "ldff1sw"),
        (.ldnf1b, 16704, "ldnf1b"), (.ldnf1h, 16705, "ldnf1h"), (.ldnf1w, 16706, "ldnf1w"), (.ldnf1d, 16707, "ldnf1d"),
        (.ldnf1sb, 16708, "ldnf1sb"), (.ldnf1sh, 16709, "ldnf1sh"), (.ldnf1sw, 16710, "ldnf1sw"),
        (.ldnt1b, 16711, "ldnt1b"), (.ldnt1h, 16712, "ldnt1h"), (.ldnt1w, 16713, "ldnt1w"), (.ldnt1d, 16714, "ldnt1d"),
        (.ldnt1sb, 16715, "ldnt1sb"), (.ldnt1sh, 16716, "ldnt1sh"), (.ldnt1sw, 16717, "ldnt1sw"),
        (.stnt1b, 16718, "stnt1b"), (.stnt1h, 16719, "stnt1h"), (.stnt1w, 16720, "stnt1w"), (.stnt1d, 16721, "stnt1d"),
        (.ld1rb, 16722, "ld1rb"), (.ld1rh, 16723, "ld1rh"), (.ld1rw, 16724, "ld1rw"), (.ld1rd, 16725, "ld1rd"),
        (.ld1rsb, 16726, "ld1rsb"), (.ld1rsh, 16727, "ld1rsh"), (.ld1rsw, 16728, "ld1rsw"),
        (.ld1rqb, 16729, "ld1rqb"), (.ld1rqh, 16730, "ld1rqh"), (.ld1rqw, 16731, "ld1rqw"), (.ld1rqd, 16732, "ld1rqd"),
        (.ld1rob, 16733, "ld1rob"), (.ld1roh, 16734, "ld1roh"), (.ld1row, 16735, "ld1row"), (.ld1rod, 16736, "ld1rod"),
        (.ld2b, 16737, "ld2b"), (.ld2h, 16738, "ld2h"), (.ld2w, 16739, "ld2w"), (.ld2d, 16740, "ld2d"), (.ld2q, 16741, "ld2q"),
        (.ld3b, 16742, "ld3b"), (.ld3h, 16743, "ld3h"), (.ld3w, 16744, "ld3w"), (.ld3d, 16745, "ld3d"), (.ld3q, 16746, "ld3q"),
        (.ld4b, 16747, "ld4b"), (.ld4h, 16748, "ld4h"), (.ld4w, 16749, "ld4w"), (.ld4d, 16750, "ld4d"), (.ld4q, 16751, "ld4q"),
        (.st2b, 16752, "st2b"), (.st2h, 16753, "st2h"), (.st2w, 16754, "st2w"), (.st2d, 16755, "st2d"), (.st2q, 16756, "st2q"),
        (.st3b, 16757, "st3b"), (.st3h, 16758, "st3h"), (.st3w, 16759, "st3w"), (.st3d, 16760, "st3d"), (.st3q, 16761, "st3q"),
        (.st4b, 16762, "st4b"), (.st4h, 16763, "st4h"), (.st4w, 16764, "st4w"), (.st4d, 16765, "st4d"), (.st4q, 16766, "st4q"),
        (.prfb, 16767, "prfb"), (.prfh, 16768, "prfh"), (.prfw, 16769, "prfw"), (.prfd, 16770, "prfd"),
        (.insr, 16771, "insr"), (.splice, 16772, "splice"), (.compact, 16773, "compact"), (.expand, 16774, "expand"),
        (.lasta, 16775, "lasta"), (.lastb, 16776, "lastb"), (.clasta, 16777, "clasta"), (.clastb, 16778, "clastb"),
        (.sunpkhi, 16779, "sunpkhi"), (.sunpklo, 16780, "sunpklo"), (.uunpkhi, 16781, "uunpkhi"), (.uunpklo, 16782, "uunpklo"),
        (.punpkhi, 16783, "punpkhi"), (.punpklo, 16784, "punpklo"),
        (.revb, 16785, "revb"), (.revh, 16786, "revh"), (.revw, 16787, "revw"), (.revd, 16788, "revd"),
        (.dupq, 16789, "dupq"), (.extq, 16790, "extq"), (.tblq, 16791, "tblq"), (.tbxq, 16792, "tbxq"),
        (.uzpq1, 16793, "uzpq1"), (.uzpq2, 16794, "uzpq2"), (.zipq1, 16795, "zipq1"), (.zipq2, 16796, "zipq2"),
        (.pmov, 16797, "pmov"), (.pmlal, 16798, "pmlal"), (.aesemc, 16799, "aesemc"), (.aesdimc, 16800, "aesdimc"),
        (.luti6, 16801, "luti6"),
    ]

    @Test func everyTokenHasItsPinnedRawValue() {
        for (mnemonic, raw, name) in Self.slab {
            #expect(mnemonic.rawValue == raw, "\(name) drifted from \(raw)")
        }
    }

    @Test func theSlabIsContiguousFrom16684() {
        // 118 tokens filling 16684...16801 with no gap and no repeat.
        let values = Self.slab.map(\.1)
        #expect(values == Array(16684 ... 16801))
        #expect(values.count == 118)
    }

    @Test func everyRawValueIsDistinct() {
        #expect(Set(Self.slab.map(\.1)).count == Self.slab.count)
    }

    @Test func theWholeSlabSitsAboveTheEarlierSVESubpieces() {
        // 2s.2-2s.4 ended at 16683; 2s.5 continues from 16684 without overlap.
        for (_, raw, name) in Self.slab {
            #expect(raw > 16683, "\(name) collides with an earlier subpiece")
            #expect(raw < 28672, "\(name) leaves the SVE slab")
        }
    }

    @Test func theTokensAreDistinctMnemonicValues() {
        #expect(Set(Self.slab.map(\.0)).count == Self.slab.count)
    }
}
