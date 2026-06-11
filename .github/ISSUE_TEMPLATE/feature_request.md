---
name: Feature request
about: An API, CLI capability, or ISA-coverage proposal
labels: enhancement
---

## What you want to do

<!-- The task, not the mechanism: "census PAC sites across a fat binary
from CI", "decode SME streaming code". -->

## What exists today and where it falls short

<!-- Which API/flag you tried, what is missing or awkward. -->

## Scope check

Iris is a disassembler. ARM64 only, decode only, one direction, no
Mach-O parsing as library API (see the "Scope & guarantees"
documentation page). Requests inside those walls are welcome. SME/SVE
decode is the flagship post-1.0 area, and contributions there must
arrive with the full trust battery (`CONTRIBUTING.md` lists exactly
what a new family decoder brings).
