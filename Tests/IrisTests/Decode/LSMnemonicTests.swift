// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Pins every L/S Mnemonic raw-value constant inside the reserved
/// 2048..4095 slab. Verifies uniqueness and range-membership; a
/// refactor that renumbers a constant is caught here.
@Suite("L/S Mnemonic constants 2048..2296")
struct LSMnemonicConstantsTests {
    /// Every L/S mnemonic at its assigned raw value. Each row is
    /// `(constant, expected, name)`.
    static let allLSMnemonics: [(Mnemonic, UInt16, String)] = [
        (.ldr, 2048, "ldr"), (.str, 2049, "str"), (.ldrb, 2050, "ldrb"),
        (.strb, 2051, "strb"), (.ldrh, 2052, "ldrh"), (.strh, 2053, "strh"),
        (.ldrsb, 2054, "ldrsb"), (.ldrsh, 2055, "ldrsh"), (.ldrsw, 2056, "ldrsw"),
        (.ldur, 2057, "ldur"), (.stur, 2058, "stur"), (.ldurb, 2059, "ldurb"),
        (.sturb, 2060, "sturb"), (.ldurh, 2061, "ldurh"), (.sturh, 2062, "sturh"),
        (.ldursb, 2063, "ldursb"), (.ldursh, 2064, "ldursh"), (.ldursw, 2065, "ldursw"),
        (.prfum, 2066, "prfum"),
        (.ldp, 2067, "ldp"), (.stp, 2068, "stp"), (.ldpsw, 2069, "ldpsw"),
        (.stgp, 2070, "stgp"), (.ldnp, 2071, "ldnp"), (.stnp, 2072, "stnp"),
        (.ldxr, 2073, "ldxr"), (.stxr, 2074, "stxr"), (.ldxrb, 2075, "ldxrb"),
        (.stxrb, 2076, "stxrb"), (.ldxrh, 2077, "ldxrh"), (.stxrh, 2078, "stxrh"),
        (.ldxp, 2079, "ldxp"), (.stxp, 2080, "stxp"), (.ldaxr, 2081, "ldaxr"),
        (.stlxr, 2082, "stlxr"), (.ldaxrb, 2083, "ldaxrb"), (.stlxrb, 2084, "stlxrb"),
        (.ldaxrh, 2085, "ldaxrh"), (.stlxrh, 2086, "stlxrh"), (.ldaxp, 2087, "ldaxp"),
        (.stlxp, 2088, "stlxp"),
        (.ldar, 2089, "ldar"), (.stlr, 2090, "stlr"), (.ldarb, 2091, "ldarb"),
        (.stlrb, 2092, "stlrb"), (.ldarh, 2093, "ldarh"), (.stlrh, 2094, "stlrh"),
        (.ldapr, 2095, "ldapr"), (.ldaprb, 2096, "ldaprb"), (.ldaprh, 2097, "ldaprh"),
        (.ldlar, 2098, "ldlar"), (.ldlarb, 2099, "ldlarb"), (.ldlarh, 2100, "ldlarh"),
        (.stllr, 2101, "stllr"), (.stllrb, 2102, "stllrb"), (.stllrh, 2103, "stllrh"),
        (.ldapur, 2104, "ldapur"), (.ldapurb, 2105, "ldapurb"), (.ldapurh, 2106, "ldapurh"),
        (.ldapursb, 2107, "ldapursb"), (.ldapursh, 2108, "ldapursh"), (.ldapursw, 2109, "ldapursw"),
        (.stlur, 2110, "stlur"), (.stlurb, 2111, "stlurb"), (.stlurh, 2112, "stlurh"),
        (.ldadd, 2113, "ldadd"), (.ldadda, 2114, "ldadda"), (.ldaddl, 2115, "ldaddl"),
        (.ldaddal, 2116, "ldaddal"), (.ldaddb, 2117, "ldaddb"), (.ldaddab, 2118, "ldaddab"),
        (.ldaddlb, 2119, "ldaddlb"), (.ldaddalb, 2120, "ldaddalb"), (.ldaddh, 2121, "ldaddh"),
        (.ldaddah, 2122, "ldaddah"), (.ldaddlh, 2123, "ldaddlh"), (.ldaddalh, 2124, "ldaddalh"),
        (.ldclr, 2125, "ldclr"), (.ldclra, 2126, "ldclra"), (.ldclrl, 2127, "ldclrl"),
        (.ldclral, 2128, "ldclral"), (.ldclrb, 2129, "ldclrb"), (.ldclrab, 2130, "ldclrab"),
        (.ldclrlb, 2131, "ldclrlb"), (.ldclralb, 2132, "ldclralb"), (.ldclrh, 2133, "ldclrh"),
        (.ldclrah, 2134, "ldclrah"), (.ldclrlh, 2135, "ldclrlh"), (.ldclralh, 2136, "ldclralh"),
        (.ldeor, 2137, "ldeor"), (.ldeora, 2138, "ldeora"), (.ldeorl, 2139, "ldeorl"),
        (.ldeoral, 2140, "ldeoral"), (.ldeorb, 2141, "ldeorb"), (.ldeorab, 2142, "ldeorab"),
        (.ldeorlb, 2143, "ldeorlb"), (.ldeoralb, 2144, "ldeoralb"), (.ldeorh, 2145, "ldeorh"),
        (.ldeorah, 2146, "ldeorah"), (.ldeorlh, 2147, "ldeorlh"), (.ldeoralh, 2148, "ldeoralh"),
        (.ldset, 2149, "ldset"), (.ldseta, 2150, "ldseta"), (.ldsetl, 2151, "ldsetl"),
        (.ldsetal, 2152, "ldsetal"), (.ldsetb, 2153, "ldsetb"), (.ldsetab, 2154, "ldsetab"),
        (.ldsetlb, 2155, "ldsetlb"), (.ldsetalb, 2156, "ldsetalb"), (.ldseth, 2157, "ldseth"),
        (.ldsetah, 2158, "ldsetah"), (.ldsetlh, 2159, "ldsetlh"), (.ldsetalh, 2160, "ldsetalh"),
        (.ldsmax, 2161, "ldsmax"), (.ldsmaxa, 2162, "ldsmaxa"), (.ldsmaxl, 2163, "ldsmaxl"),
        (.ldsmaxal, 2164, "ldsmaxal"), (.ldsmaxb, 2165, "ldsmaxb"), (.ldsmaxab, 2166, "ldsmaxab"),
        (.ldsmaxlb, 2167, "ldsmaxlb"), (.ldsmaxalb, 2168, "ldsmaxalb"), (.ldsmaxh, 2169, "ldsmaxh"),
        (.ldsmaxah, 2170, "ldsmaxah"), (.ldsmaxlh, 2171, "ldsmaxlh"), (.ldsmaxalh, 2172, "ldsmaxalh"),
        (.ldsmin, 2173, "ldsmin"), (.ldsmina, 2174, "ldsmina"), (.ldsminl, 2175, "ldsminl"),
        (.ldsminal, 2176, "ldsminal"), (.ldsminb, 2177, "ldsminb"), (.ldsminab, 2178, "ldsminab"),
        (.ldsminlb, 2179, "ldsminlb"), (.ldsminalb, 2180, "ldsminalb"), (.ldsminh, 2181, "ldsminh"),
        (.ldsminah, 2182, "ldsminah"), (.ldsminlh, 2183, "ldsminlh"), (.ldsminalh, 2184, "ldsminalh"),
        (.ldumax, 2185, "ldumax"), (.ldumaxa, 2186, "ldumaxa"), (.ldumaxl, 2187, "ldumaxl"),
        (.ldumaxal, 2188, "ldumaxal"), (.ldumaxb, 2189, "ldumaxb"), (.ldumaxab, 2190, "ldumaxab"),
        (.ldumaxlb, 2191, "ldumaxlb"), (.ldumaxalb, 2192, "ldumaxalb"), (.ldumaxh, 2193, "ldumaxh"),
        (.ldumaxah, 2194, "ldumaxah"), (.ldumaxlh, 2195, "ldumaxlh"), (.ldumaxalh, 2196, "ldumaxalh"),
        (.ldumin, 2197, "ldumin"), (.ldumina, 2198, "ldumina"), (.lduminl, 2199, "lduminl"),
        (.lduminal, 2200, "lduminal"), (.lduminb, 2201, "lduminb"), (.lduminab, 2202, "lduminab"),
        (.lduminlb, 2203, "lduminlb"), (.lduminalb, 2204, "lduminalb"), (.lduminh, 2205, "lduminh"),
        (.lduminah, 2206, "lduminah"), (.lduminlh, 2207, "lduminlh"), (.lduminalh, 2208, "lduminalh"),
        (.swp, 2209, "swp"), (.swpa, 2210, "swpa"), (.swpl, 2211, "swpl"),
        (.swpal, 2212, "swpal"), (.swpb, 2213, "swpb"), (.swpab, 2214, "swpab"),
        (.swplb, 2215, "swplb"), (.swpalb, 2216, "swpalb"), (.swph, 2217, "swph"),
        (.swpah, 2218, "swpah"), (.swplh, 2219, "swplh"), (.swpalh, 2220, "swpalh"),
        (.stadd, 2221, "stadd"), (.staddl, 2222, "staddl"), (.staddb, 2223, "staddb"),
        (.staddlb, 2224, "staddlb"), (.staddh, 2225, "staddh"), (.staddlh, 2226, "staddlh"),
        (.stclr, 2227, "stclr"), (.stclrl, 2228, "stclrl"), (.stclrb, 2229, "stclrb"),
        (.stclrlb, 2230, "stclrlb"), (.stclrh, 2231, "stclrh"), (.stclrlh, 2232, "stclrlh"),
        (.steor, 2233, "steor"), (.steorl, 2234, "steorl"), (.steorb, 2235, "steorb"),
        (.steorlb, 2236, "steorlb"), (.steorh, 2237, "steorh"), (.steorlh, 2238, "steorlh"),
        (.stset, 2239, "stset"), (.stsetl, 2240, "stsetl"), (.stsetb, 2241, "stsetb"),
        (.stsetlb, 2242, "stsetlb"), (.stseth, 2243, "stseth"), (.stsetlh, 2244, "stsetlh"),
        (.stsmax, 2245, "stsmax"), (.stsmaxl, 2246, "stsmaxl"), (.stsmaxb, 2247, "stsmaxb"),
        (.stsmaxlb, 2248, "stsmaxlb"), (.stsmaxh, 2249, "stsmaxh"), (.stsmaxlh, 2250, "stsmaxlh"),
        (.stsmin, 2251, "stsmin"), (.stsminl, 2252, "stsminl"), (.stsminb, 2253, "stsminb"),
        (.stsminlb, 2254, "stsminlb"), (.stsminh, 2255, "stsminh"), (.stsminlh, 2256, "stsminlh"),
        (.stumax, 2257, "stumax"), (.stumaxl, 2258, "stumaxl"), (.stumaxb, 2259, "stumaxb"),
        (.stumaxlb, 2260, "stumaxlb"), (.stumaxh, 2261, "stumaxh"), (.stumaxlh, 2262, "stumaxlh"),
        (.stumin, 2263, "stumin"), (.stuminl, 2264, "stuminl"), (.stuminb, 2265, "stuminb"),
        (.stuminlb, 2266, "stuminlb"), (.stuminh, 2267, "stuminh"), (.stuminlh, 2268, "stuminlh"),
        (.cas, 2269, "cas"), (.casa, 2270, "casa"), (.casl, 2271, "casl"),
        (.casal, 2272, "casal"), (.casb, 2273, "casb"), (.casab, 2274, "casab"),
        (.caslb, 2275, "caslb"), (.casalb, 2276, "casalb"), (.cash, 2277, "cash"),
        (.casah, 2278, "casah"), (.caslh, 2279, "caslh"), (.casalh, 2280, "casalh"),
        (.casp, 2281, "casp"), (.caspa, 2282, "caspa"), (.caspl, 2283, "caspl"),
        (.caspal, 2284, "caspal"),
        (.prfm, 2285, "prfm"),
        (.ldraa, 2286, "ldraa"), (.ldrab, 2287, "ldrab"),
        (.ldtr, 2288, "ldtr"), (.sttr, 2289, "sttr"), (.ldtrb, 2290, "ldtrb"),
        (.sttrb, 2291, "sttrb"), (.ldtrh, 2292, "ldtrh"), (.sttrh, 2293, "sttrh"),
        (.ldtrsb, 2294, "ldtrsb"), (.ldtrsh, 2295, "ldtrsh"), (.ldtrsw, 2296, "ldtrsw"),
    ]

    @Test func everyMnemonicHasItsLockedRawValue() {
        for (mnemonic, expected, name) in Self.allLSMnemonics {
            #expect(mnemonic.rawValue == expected, "Mnemonic.\(name) raw value drifted")
        }
    }

    @Test func everyMnemonicFallsInTheReservedSlab() {
        let lsSlab: ClosedRange<UInt16> = 2048 ... 4095
        for (mnemonic, _, name) in Self.allLSMnemonics {
            #expect(lsSlab.contains(mnemonic.rawValue), "Mnemonic.\(name) outside the L/S slab")
        }
    }

    @Test func everyRawValueIsUnique() {
        var seen: [UInt16: String] = [:]
        for (mnemonic, _, name) in Self.allLSMnemonics {
            let prior = seen.updateValue(name, forKey: mnemonic.rawValue)
            #expect(
                prior == nil,
                "Mnemonic.\(name) collides with .\(prior ?? "<none>") at \(mnemonic.rawValue)",
            )
        }
    }

    @Test func rangeAllocationNamesTheSlab() {
        let lsEntry = Mnemonic.allocations.first { $0.label == "Loads & Stores" }
        #expect(lsEntry?.range == 2048 ... 4095)
    }

    @Test func tableCountMatchesTheAllocation() {
        // 249 distinct constants — the full L/S mnemonic surface, raw
        // values 2048..2296 contiguous.
        #expect(Self.allLSMnemonics.count == 249)
    }
}
