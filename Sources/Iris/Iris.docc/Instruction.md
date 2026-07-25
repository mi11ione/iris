# ``Iris/Instruction``

## Topics

### Core fields

- ``address``
- ``encoding``
- ``mnemonic``
- ``text``
- ``operands``
- ``category``

### Control flow

- ``isCall``
- ``isReturn``
- ``isConditional``
- ``branchClass``
- ``branchTarget``
- ``pcRelativeTarget``

### Memory behavior

- ``readsMemory``
- ``writesMemory``
- ``isAtomic``
- ``isExclusive``
- ``memoryAccess``
- ``memoryOrdering``

### Register dataflow

- ``semanticReads``
- ``semanticWrites``

### Scalable state (SVE / SME)

- ``scalableReads``
- ``scalableWrites``
- ``scalableEffect``

### Condition flags

- ``readsFlags``
- ``writesFlags``
- ``flagEffect``

### Pointer authentication

- ``usesPointerAuthentication``

### Provenance

- ``isUndefined``

### Constructing one

- ``init(address:encoding:mnemonic:semanticReads:semanticWrites:branchClass:memoryAccess:memoryOrdering:flagEffect:category:operands:scalableReads:scalableWrites:scalableEffect:)``
- ``Operands``
