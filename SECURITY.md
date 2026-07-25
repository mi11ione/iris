# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| latest 0.x release | ✅ |
| anything older | ❌ |

During 0.x only the most recent release gets security fixes. From 1.0 this widens to the current major version.

## Reporting a vulnerability

Report privately through [GitHub's private vulnerability reporting](https://github.com/mi11ione/iris/security/advisories/new) (Security tab → "Report a vulnerability"). Please don't open a public issue for anything you believe is exploitable.

Expect an acknowledgement within a few days. Confirmed issues are fixed in the next release and credited to the reporter unless you'd rather stay anonymous.

## What counts as a security issue

iris reads attacker-controllable bytes and must stay safe whatever they contain. The contract is total, crash-free decode: hostile input produces diagnostics, never a crash or undefined behavior. In scope:

- **Any crash on hostile input** — a Mach-O file or `--bytes` string that makes the CLI or the library trap, SIGSEGV/SIGBUS, or abort.
- **Memory unsafety** — reads or writes outside the mapped file window, or any other undefined behavior.
- **Resource-exhaustion amplification** — small crafted inputs causing unbounded memory growth or non-terminating parsing, beyond the file's own size driving proportional work.

Out of scope, file a regular issue instead: wrong disassembly text or semantics (a correctness bug — that's what the parity harness is for), crashes of the development-only tools (`iris-parity`, benchmarks) on their own inputs, and anything requiring a modified build. iris performs no network access and never executes the code it disassembles.
