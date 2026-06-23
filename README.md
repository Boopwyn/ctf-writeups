# CTF Writeups

--- 

##  Resources

Useful links

### Reverse Engineering

- [Z3](https://www.fweefwop.club/activities/reverse_engineering_with_z3.pdf)  
- [angr](https://docs.angr.io/en/latest/examples.html)

### pwn

`kitty-pwn` is a small wrapper script used to launch a GDB session inside a separate `kitty` terminal window when using Hyprland. Eg. see [spill_the_t](./DisorientationCTF/pwn/spill_the_t/solve.py), useful for dynamically inspecting the state of the heap bins!

```bash
#!/bin/sh
exec kitty --hold sh -c "$*"
```
