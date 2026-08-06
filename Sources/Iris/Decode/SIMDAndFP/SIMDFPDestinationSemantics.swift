// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Whether a SIMD/FP mnemonic's destination is also a source (destructive or
/// accumulating).
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
         .bfmlalb, .bfmlalt, .bfmmla, .fmmla,
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
