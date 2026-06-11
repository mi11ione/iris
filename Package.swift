// swift-tools-version: 6.0
// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import PackageDescription

let package = Package(
    name: "iris",
    products: [
        .library(
            name: "Iris",
            targets: ["Iris"],
        ),
        .executable(
            name: "iris",
            targets: ["iris-cli"],
        ),
    ],
    targets: [
        .target(
            name: "Iris",
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ],
        ),
        // CLI logic lives in a non-product library target so it is unit-testable;
        // the Mach-O walker inside it is deliberately NOT public API.
        .target(
            name: "IrisCLICore",
            dependencies: ["Iris"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ],
        ),
        .executableTarget(
            name: "iris-cli",
            dependencies: ["Iris", "IrisCLICore"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ],
        ),
        // In-repo trust instrument: llvm-mc parity + exhaustive sweeps.
        // Not a published product.
        .executableTarget(
            name: "iris-parity",
            dependencies: ["Iris"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ],
        ),
        .testTarget(
            name: "IrisTests",
            dependencies: ["Iris"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ],
        ),
        .testTarget(
            name: "IrisCLITests",
            dependencies: ["IrisCLICore", "Iris"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ],
        ),
    ],
)
