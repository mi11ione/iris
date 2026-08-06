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
        // Iris.docc is excluded from the module's file set because SwiftPM's
        // Swift Build path is not given the `.docc` ignore rule its native path
        // has (swiftlang/swift-package-manager#10295, cherry-picked to 6.4.x in
        // #10329), so the catalogue reads there as an unhandled file and warns.
        // Declaring it a resource instead silences the warning by generating a
        // Foundation-importing, fatalError-carrying bundle accessor into the
        // library, which the zero-import contract forbids. The catalogue is
        // still built into the documentation: .spi.yml hands DocC its path.
        .target(
            name: "Iris",
            exclude: ["Iris.docc"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ],
        ),
        // The validation oracle
        .target(
            name: "IrisValidation",
            dependencies: ["Iris"],
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
            dependencies: ["Iris", "IrisValidation"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ],
        ),
        .testTarget(
            name: "IrisTests",
            dependencies: ["Iris", "IrisValidation"],
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
