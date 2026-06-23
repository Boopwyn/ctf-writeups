# CTF Writeups

--- 

##  Resources

Useful links

### Reverse Engineering

- [Z3](https://www.fweefwop.club/activities/reverse_engineering_with_z3.pdf)  

You can also use/model functions:
```python
#!/usr/bin/env python3

from typing import List, Tuple
from z3 import *

U64_MASK = (1 << 64) - 1

def xorshift128p_z3(s0: BitVec, s1: BitVec) -> Tuple[BitVec, BitVec, BitVec]:
    # 2. Model the xorshift128p function symbolically.
    #    In most cases, you can just use the standard Python operators
    #    (e.g., &, ^, +, and <<). However, in some other cases you must use
    #    the Z3 functions (e.g., logical shift right is `LShR`).
    init_t = s0 & U64_MASK
    init_s = s1 & U64_MASK

    t = init_t
    s = init_s

    t ^= (t << 23) & U64_MASK
    t ^= (LShR(t, 18)) & U64_MASK
    t ^= (s ^ LShR(s, 5)) & U64_MASK

    updated_s0 = init_s & U64_MASK
    updated_s1 = t & U64_MASK

    return (t + s) & U64_MASK, updated_s0, updated_s1


s0 = BitVec("s0", 64)
s1 = BitVec("s1", 64)

r1, s0_1, s1_1 = xorshift128p_z3(s0, s1)
r2, s0_2, s1_2 = xorshift128p_z3(s0_1, s1_1)
r3, s0_3, s1_3 = xorshift128p_z3(s0_2, s1_2)

solver = Solver()
solver.add(r1 == 8388645)
solver.add(r2 == 33816707)
solver.add(r3 == 70368778527840)

if solver.check() == sat:
    model = solver.model()
    s0_init = model[s0].as_long()
    s1_init = model[s1].as_long()
    print(f"initial seed -> [{s0_init:#0x}, {s1_init:#0x}]")
else:
    print("UNSAT!")
```

- [angr](https://docs.angr.io/en/latest/examples.html)

### pwn

`kitty-pwn` is a small wrapper script used to launch a GDB session inside a separate `kitty` terminal window when using Hyprland. Eg. see [spill_the_t](./DisorientationCTF/pwn/spill_the_t/solve.py), useful for dynamically inspecting the state of the heap bins!

```bash
#!/bin/sh
exec kitty --hold sh -c "$*"
```
