# Security Policy

## Reporting a vulnerability

Report privately through [GitHub's private vulnerability reporting](https://github.com/mi11ione/iris/security/advisories/new) (Security tab → "Report a vulnerability"). Please don't open a public issue for anything you believe is exploitable.

Expect an acknowledgement within a few days. Confirmed issues are fixed in the next release and credited to the reporter unless you'd rather stay anonymous.

## What counts

iris reads attacker-controllable bytes and must stay safe whatever they contain: hostile input produces diagnostics, never a crash or undefined behavior. In scope are any crash on hostile input (a Mach-O file or `--bytes` string that traps, SIGSEGVs or aborts the CLI or the library), memory unsafety (reads or writes outside the mapped file window), and resource-exhaustion amplification (small crafted inputs causing unbounded memory growth or non-terminating parsing).

File a regular issue instead for wrong disassembly text or semantics, crashes of the development-only tools (`iris-parity`, benchmarks) on their own inputs, and anything requiring a modified build. iris performs no network access and never executes the code it disassembles.
