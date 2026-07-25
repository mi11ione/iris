// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The one semantic-attribute fact the SIMD/FP decoders themselves need while
// forming a record: whether a mnemonic's destination is also a source. The
// validation oracle in `IrisValidation` carries its own transcription of the
// same architectural fact, deliberately not shared with this one — an oracle
// that reused the decoder's table could not catch an error in it.

/// Whether the destination operand of a SIMD/FP mnemonic is also a
/// source (destructive / accumulating semantics).
/// NOTE: FMADD/FMSUB/FNMADD/FNMSUB are 4-operand instructions where
/// Va (operand[3]) is the accumulator — Rd (operand[0]) is a pure
/// write. They are NOT destination-reads-itself; their accumulator
/// is the explicit Ra operand.
@_effects(readonly)
func simdFPDestinationReadsItself(_ m: Mnemonic) -> Bool {
    switch m {
    case .mla, .mls, .fmla, .fmls, .fmlal, .fmlal2, .fmlsl, .fmlsl2,
         .fcmla, .fdot, .fmlalb, .fmlalt, .fmlallbb, .fmlallbt, .fmlalltb, .fmlalltt,
         .sqdmlal, .sqdmlsl, .sqdmlal2, .sqdmlsl2,
         .sqrdmlah, .sqrdmlsh,
         .smlal, .smlal2, .smlsl, .smlsl2,
         .umlal, .umlal2, .umlsl, .umlsl2,
         .sdot, .udot, .usdot, .sudot, .bfdot,
         .bfmlalb, .bfmlalt, .bfmmla,
         .smmla, .ummla, .usmmla,
         .sadalp, .uadalp,
         .saba, .uaba, .sabal, .sabal2, .uabal, .uabal2,
         .bsl, .bit, .bif,
         .ins, .sli, .sri, .tbx:
        true
    default:
        false
    }
}
