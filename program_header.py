"""
    Represent a program header.
    Note: all fields are strings. They are reversed (little endian) already.
"""


from util import read_bytes


class PROGRAM_HEADER(object):
    def __init__(self, bytes: bytearray, index, isThirtyTwo):
        self.bytes = bytes
        self.index = index
        self.isThirtyTwo = isThirtyTwo
        self.type = read_bytes(self.bytes, 0, count=4)
        self.flags = None
        self.offset = None
        self.vaddr = None
        self.paddr = None
        self.size_file = None
        self.size_mem = None
        self.align = None

        if self.isThirtyTwo:
            self.parse_thirty_two()
        else:
            self.parse_sixty_four()

    def parse_thirty_two(self):
        self.flags = read_bytes(self.bytes, 24, end=28)
        self.offset = read_bytes(self.bytes, 4, end=8)
        self.vaddr = read_bytes(self.bytes, 8, end=12)
        self.paddr = read_bytes(self.bytes, 12, end=16)
        self.size_file = read_bytes(self.bytes, 16, end=20)
        self.size_mem = read_bytes(self.bytes, 20, end=24)
        self.align = read_bytes(self.bytes, 28, end=32)

    def parse_sixty_four(self):
        self.flags = read_bytes(self.bytes, 4, end=8)
        self.offset = read_bytes(self.bytes, 8, end=16)
        self.vaddr = read_bytes(self.bytes, 16, end=24)
        self.paddr = read_bytes(self.bytes, 24, end=32)
        self.size_file = read_bytes(self.bytes, 32, end=40)
        self.size_mem = read_bytes(self.bytes, 40, end=48)
        self.align = read_bytes(self.bytes, 48, end=56)

    def type_to_string(self) -> str:
        if self.type == "00000000":
            return "NULL"
        elif self.type == "00000001":
            return "LOAD"
        elif self.type == "00000002":
            return "DYNAMIC"
        elif self.type == "00000003":
            return "INTERP"
        elif self.type == "00000004":
            return "NOTE"
        elif self.type == "00000005":
            return "SHLIB"
        elif self.type == "00000006":
            return "PHDR"
        elif self.type == "00000007":
            return "TLS"
        elif self.type == "60000000":
            return "LOOS"
        elif self.type == "6FFFFFFF":
            return "HIOS"
        elif self.type == "70000000":
            return "LOPROC"
        elif self.type == "7FFFFFFF":
            return "HIPROC"
        elif self.type == "6474e550":
            return "GNU_EH_FRAME"
        elif self.type == "6474e551":
            return "GNU_STACK"
        elif self.type == "6474e552":
            return "GNU_RELRO"
        else:
            return f"Unknown Type (read {self.type})"

    def flag_to_string(self) -> str:
        # TODO: there is probably a smarter/more pythonic way to do this
        # R W E (4 = read, 2 = write, 1 = exe)
        flag = ["R", "W", "E"]
        binary_flags = [int(f) for f in bin(int(self.flags.lstrip("0")))[2:]]
        string_flags = [flag[i] if b == 1 else "-" for i,
                        b in enumerate(binary_flags)]
        return "".join(string_flags)

    def __str__(self):
        return f"{self.type_to_string():<15}\t"\
            f"0x{self.vaddr:<20}\t"\
            f"0x{self.paddr:<20}\t"\
            f"0x{self.offset.lstrip('0'):<8}\t"\
            f"0x{self.size_file.lstrip('0'):<8}\t"\
            f"0x{self.size_mem.lstrip('0'):<8}\t"\
            f"{self.flag_to_string():<8}"\
            f"0x{self.align.lstrip('0'):<8}\t"
