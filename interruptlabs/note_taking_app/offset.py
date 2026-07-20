from pwn import *

# Should be 216 via static analysis just a sanity check
c = cyclic(256,n=8) 
print(f"payload: {c}")

offset = c.find(p64(0x6261616161616163))
print(f"return address offset = {offset}")
