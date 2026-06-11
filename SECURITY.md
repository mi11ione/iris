# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| latest 0.x release | ✅ |
| anything older | ❌ |

During the 0.x window only the most recent release receives security fixes.
From 1.0 this table will widen to the current major version.

## Reporting a Vulnerability

Report vulnerabilities privately through [GitHub's private vulnerability
reporting](https://github.com/mi11ione/iris/security/advisories/new) on this
repository (Security tab → "Report a vulnerability"). Please do not open a
public issue for anything you believe is exploitable. For everything else the
regular issue tracker is the right place.

You can expect an acknowledgement within a few days. Confirmed issues are fixed
in the next release, credited to the reporter unless anonymity is requested.

## What counts as a security issue here

Iris is a disassembler: it reads attacker-controllable bytes (Mach-O files,
raw byte strings) and must stay safe no matter what they contain. The library's
contract is total, crash-free decode. A fuzzed or adversarial input must
produce diagnostics, never a crash or undefined behavior (the documented
totality guarantee, described in *Scope & guarantees* in the DocC
documentation). Treat these as security issues, in scope for private reporting:

- **Any crash on hostile input.** A Mach-O file or `--bytes` string that makes
  the `iris` CLI or the `Iris` library trap, SIGSEGV/SIGBUS, or abort violates
  the never-crash contract and is a vulnerability.
- **Memory unsafety.** Any input that causes reads or writes outside the
  mapped file window or other undefined behavior.
- **Resource-exhaustion amplification.** Crafted small inputs that cause
  unbounded memory growth or non-terminating parsing (beyond the file's own
  size driving proportional work).

Out of scope for the security process (file a regular issue instead):
incorrect disassembly text or semantics for some encoding (a correctness bug,
which the parity harness exists for), crashes of the development-only
tools (`iris-parity`, benchmarks) on their own inputs, and anything requiring
a modified build. Iris performs no network access and never executes the code
it disassembles. Reports assuming otherwise are likely out of scope.
