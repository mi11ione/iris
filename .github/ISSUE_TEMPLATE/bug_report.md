---
name: Bug report
about: A decode divergence, a crash, or any behavior that breaks a documented guarantee
labels: bug
---

## What happened

<!-- One or two sentences. -->

## For decoder bugs (wrong mnemonic / operands / semantics / text)

The fastest path to a fix is the exact word plus the oracle's reading:

- **Encoding (hex word):** e.g. `0x91040108`
- **Features:** plain ARM64 or `arm64e`
- **Iris output:** the `iris 0x<word>` line (or `instruction.text` /
  the semantic field you believe is wrong)
- **Expected `llvm-mc` output:**

```sh
# macOS: brew install llvm
echo "0x08 0x01 0x04 0x91" | llvm-mc --disassemble --triple=arm64-apple-macos --mattr=+all
```

Check `KNOWN-DEVIATIONS.md` first. A catalogued divergence is
expected behavior with evidence on file.

## For CLI or library bugs

- **Command or code:** the smallest invocation/snippet that reproduces it
- **What you expected / what you got** (attach the binary or a byte excerpt
  if the input matters and you can share it)
- **Platform:** macOS/Linux, Swift version, Iris version (`iris --version`)
