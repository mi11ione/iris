// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import IrisCLICore

let status = CLI.run(
    arguments: Array(CommandLine.arguments.dropFirst()),
    standardOutputIsTTY: isatty(STDOUT_FILENO) != 0,
    writeOutput: { FileHandle.standardOutput.write(Data($0.utf8)) },
    writeError: { FileHandle.standardError.write(Data($0.utf8)) },
)
exit(status)
