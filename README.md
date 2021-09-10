# rop_gadget_finder
A simple python tool to find ROP Gadget in Linux ELF binaries

### Prerequisites
Uses some third party libraries:

* argparse : For parsing command line arguments
* capstone : For decoding the opcodes

Both can be installed by running `pip install -r requirements.txt`.

We also need **twelfe**, a python libary to parse ELF files.
This module can be found at [twelfe github](https://github.com/G-Nils/twelfe).

**Disclaimer**: I am also the author of the *twelfe* module.


### Examples

Show help:

```console
$ python3 rop_gadget_finder.py --help

usage: rop_gadget_finder.py [-h] -e EXECUTABLE [-s SIZE] [-o OUTPUT] [-f FORMAT] [-g GADGET]

optional arguments:
  -h, --help            show this help message and exit
  -e EXECUTABLE, --executable EXECUTABLE
                        Path to executable
  -s SIZE, --size SIZE  Amount of instructions before a 'ret' (default=3)
  -o OUTPUT, --output OUTPUT
                        Path to output file
  -f FORMAT, --format FORMAT
                        Output format (g(reppable), s(tandard)). (default = s)
  -g GADGET, --gadget GADGET
                        Search term to filter for (e.g. pop rbp)
```

Show all gadgets:

```console
$ python3 rop_gadget_finder.py -e test
Starting rop_gadget_finder with following paramters:
Executable:             test
Size:                   3
Writing to file:        False ()
Output format:          s

Searching in section: .init: 0x1000 - 0x1017
Searching in section: .plt: 0x1020 - 0x1040
Searching in section: .plt.got: 0x1040 - 0x1048
Searching in section: .text: 0x1050 - 0x11f1
Searching in section: .fini: 0x11f4 - 0x11fd
0x1012  add     rsp, 8
0x1016  ret

0x1004  mov     rax, qword ptr [rip + 0x2fdd]
0x100b  test    rax, rax
0x100e  je      0x1012
0x1010  call    rax

0x1067  lea     ecx, [rip + 0x123]
0x106d  lea     rdi, [rip + 0xe7]
0x1074  call    qword ptr [rip + 0x2f66]

0x1068  or      eax, 0x123
0x106d  lea     rdi, [rip + 0xe7]
0x1074  call    qword ptr [rip + 0x2f66]

...

0x11e6  pop     r13
0x11e8  pop     r14
0x11ea  pop     r15
0x11ec  ret


Found 106 gadgets

```

Filter for gadget:

```console
$ python3 rop_gadget_finder.py -e test --gadget "pop rbp"

Starting rop_gadget_finder with following parameters:
Executable:             test
Size:                   3
Writing to file:        False ()
Output format:          s

Searching in section: .init: 0x1000 - 0x1017
Searching in section: .plt: 0x1020 - 0x1040
Searching in section: .plt.got: 0x1040 - 0x1048
Searching in section: .text: 0x1050 - 0x11f1
Searching in section: .fini: 0x11f4 - 0x11fd
0x1113  call    0x1080
0x1118  mov     byte ptr [rip + 0x2f11], 1
0x111f  pop     rbp
0x1120  ret

0x1145  nop
0x1146  pop     rbp
0x1147  ret

...

0x1158  nop
0x1159  pop     rbp
0x115a  ret

0x1159  pop     rbp
0x115a  ret


Found 25 gadgets
```

Limit the size of the gadgets:

```consle
$ python3 rop_gadget_finder.py -e test --size 1

Starting rop_gadget_finder with following parameters:
Executable:             test
Size:                   1
Writing to file:        False ()
Output format:          s

Searching in section: .init: 0x1000 - 0x1017
Searching in section: .plt: 0x1020 - 0x1040
Searching in section: .plt.got: 0x1040 - 0x1048
Searching in section: .text: 0x1050 - 0x11f1
Searching in section: .fini: 0x11f4 - 0x11fd
0x1012  add     rsp, 8
0x1016  ret

0x100e  je      0x1012
0x1010  call    rax

0x106d  lea     rdi, [rip + 0xe7]
0x1074  call    qword ptr [rip + 0x2f66]

...

0x11ea  pop     r15
0x11ec  ret

```

### Other
A 64-bit binary (*test*) is attached. The source code can be found in *test.c*.