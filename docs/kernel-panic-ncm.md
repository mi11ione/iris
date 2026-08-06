# Root-causing a kernel panic with `iris --bytes`

macOS 27.0 beta (26A5353q), Apple M4. Attaching an iPhone over USB with Personal Hotspot enabled but routed over Wi-Fi panics the kernel: `Kernel data abort`, `esr 0x96000005`, `far=0x0`.

The evidence is a 515 MB `MH_CORE` with 60,742 segments and a closed-source kext. There is no file to point a disassembler at — only bytes at an address.

## The faulting sequence

`IOEventSource::closeGate()`, three words read out of the core:

```sh
$ iris --bytes "f3 03 00 aa 60 1a 40 f9 10 00 40 f9" --semantics
0: aa0003f3  mov x19, x0                                 ; reads=x0 writes=x19
4: f9401a60  ldr x0, [x19, #48]                          ; reads=x19 writes=x0 mem=load
8: f9400010  ldr x16, [x0]                               ; reads=x0 writes=x16 mem=load
```

`+48` is `IOEventSource::workLoop`. The second load reads `x0` — the value the first load produced. With `far=0x0`, `workLoop` was NULL and the panic is the vtable load through it. `reads=x0` names the faulting register without reading the addressing mode.

The same basic block continues into live PAC, which decodes on the base ISA:

```sh
$ iris --bytes "10 1a c1 da 10 82 06 91 00 08 3f d7" --semantics
0: dac11a10  autda x16, x16                              ; reads=x16 writes=x16
4: 91068210  add x16, x16, #416                          ; reads=x16 writes=x16
8: d73f0800  blraa x0, x0                                ; reads=x0 writes=x30 branch=call
```

`+416` is `IOWorkLoop::closeGate` in the vtable.

## The race

Disassembling `AppleUSBNCMDataPoller::checkForWork` gave the window: it calls `openGate()` at `+0x50` to drop the work-loop gate for the slow USB RX drain, then `closeGate()` at `+0xd8` to re-acquire. Nothing re-validates `workLoop` in between. Teardown ran `removeEventSource` inside that window, clearing `workLoop`; the re-acquire dereferenced NULL.

Heap state settled it: the poller was off the work loop's event-source chain, `enabled=0`, `workLoop=NULL`, while its `checkForWork` was still on the stack.

## Pipeline use

The same words as NDJSON, which is how the analysis scripts consumed them:

```sh
$ iris --json --slim --bytes "60 1a 40 f9 10 00 40 f9"
{"address":"0x0","encoding":"0xf9401a60","mnemonic":"ldr","text":"ldr x0, [x19, #48]","category":"loadsAndStores","operands":["x0","[x19, #48]"],"reads":["x19"],"writes":["x0"],"memoryAccess":"load"}
{"address":"0x4","encoding":"0xf9400010","mnemonic":"ldr","text":"ldr x16, [x0]","category":"loadsAndStores","operands":["x16","[x0]"],"reads":["x0"],"writes":["x16"],"memoryAccess":"load"}
```

Byte-stable output meant the decode step cached across roughly 40 throwaway core-walking scripts.

## Outcome

Reported to Apple. Observed as a local DoS; the same race admits a use-after-free if teardown drops the event source's last reference inside the dropped-gate window, since `IOWorkLoop::runEventSources` iterates the chain without retaining.
