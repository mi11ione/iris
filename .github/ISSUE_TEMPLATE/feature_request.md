---
name: Feature request
about: An API, CLI capability, or ISA-coverage proposal
labels: enhancement
---

## What you want to do

<!-- The task, not the mechanism: "census PAC sites across a fat binary from
CI", "get ZA tile writes out of the JSON stream". -->

## What exists and where it falls short

<!-- Which API or flag you tried, and what is missing or awkward. -->

## Before you file

iris decodes ARM64, one direction, and ships no Mach-O parsing as library API.

ISA coverage is complete through the v9.6-era extensions llvm-mc recognizes, SVE/SVE2 and SME/SME2 included, so a coverage report is most useful as a specific encoding that decodes wrong or not at all. New decode work arrives with the full trust battery — [`CONTRIBUTING.md`](../../CONTRIBUTING.md) lists what a new family decoder brings.
