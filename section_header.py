"""
    Represent a section header.
    Note: all fields are strings. They are reversed (little endian) already.
"""


from util import read_bytes


class SECTION_HEADER(object):
    def __init__(self, bytes: bytearray, index: int, isThirtyTwo: bool) -> None:
        self.bytes = bytes
        self.index = index
        self.isThirtyTwo = isThirtyTwo
        self.name_offset = read_bytes(self.bytes, 0, end=4)
        self.name = None
        self.type = read_bytes(self.bytes, 4, end=8)
        self.flags = None
        self.addr = None
        self.offset = None
        self.size = None
        self.link = None
        self.info = None
        self.align = None
        self.size_entry = None

        if self.isThirtyTwo:
            self.parse_thirty_two()
        else:
            self.parse_sixty_four()

    def parse_thirty_two(self):
        self.flags = read_bytes(self.bytes, 8, end=12)
        self.addr = read_bytes(self.bytes, 12, end=16)
        self.offset = read_bytes(self.bytes, 16, end=20)
        self.size = read_bytes(self.bytes, 20, end=24)
        self.link = read_bytes(self.bytes, 24, end=28)
        self.info = read_bytes(self.bytes, 28, end=32)
        self.align = read_bytes(self.bytes, 32, end=36)
        self.size_entry = read_bytes(self.bytes, 36, end=40)

    def parse_sixty_four(self):
        self.flags = read_bytes(self.bytes, 8, end=16)
        self.addr = read_bytes(self.bytes, 16, end=24)
        self.offset = read_bytes(self.bytes, 24, end=32)
        self.size = read_bytes(self.bytes, 32, end=40)
        self.link = read_bytes(self.bytes, 40, end=44)
        self.info = read_bytes(self.bytes, 44, end=48)
        self.align = read_bytes(self.bytes, 48, end=56)
        self.size_entry = read_bytes(self.bytes, 56, end=64)

    def type_to_string(self) -> str:
        if self.type == "00000000":
            return "NULL"
        elif self.type == "00000001":
            return "PROGBITS"
        elif self.type == "00000002":
            return "SMTAB"
        elif self.type == "00000003":
            return "STRTAB"
        elif self.type == "00000004":
            return "RELA"
        elif self.type == "00000005":
            return "HASH"
        elif self.type == "00000006":
            return "DYNAMIC"
        elif self.type == "00000007":
            return "NOTE"
        elif self.type == "00000008":
            return "NOBITS"
        elif self.type == "00000009":
            return "REL"
        elif self.type == "0000000a":
            return "SHLIB"
        elif self.type == "0000000b":
            return "DYNSYM"
        elif self.type == "0000000e":
            return "INIT_ARRAY"
        elif self.type == "0000000f":
            return "FINI_ARRAY"
        elif self.type == "00000001":
            return "PROGBITS"
        elif self.type == "00000010":
            return "PREINIT_ARRAY"
        elif self.type == "00000001":
            return "PROGBITS"
        elif self.type == "00000011":
            return "GROUP"
        elif self.type == "00000012":
            return "SYMTAB_SHNDX"
        elif self.type == "000000013":
            return "NUM"
        elif self.type == "6ffffff6":
            return "GNU_HASH"
        elif self.type == "6fffffff":
            return "VERSYM"
        elif self.type == "6ffffffe":
            return "VERNEED"
        else:
            return f"Unknown type (read {self.type})"

    def flags_to_string(self) -> str:
        flag_str = []
        # String to hex, convert to binary, reverse
        binary_flag = format(int(self.flags, 16), "032b")[::-1]

        if binary_flag[0] == "1":
            flag_str.append("W")

        if binary_flag[1] == "1":
            flag_str.append("A")

        if binary_flag[2] == "1":
            flag_str.append("X")

        if binary_flag[4] == "1":
            flag_str.append("M")

        if binary_flag[5] == "1":
            flag_str.append("S")

        if binary_flag[6] == "1":
            flag_str.append("I")

        if binary_flag[7] == "1":
            flag_str.append("O")

        if binary_flag[8] == "8":
            flag_str.append("N")

        if binary_flag[9] == "1":
            flag_str.append("G")

        if binary_flag[10] == "1":
            flag_str.append("T")

        # Currently ignoring the rare flags

        return "".join(flag_str)

    def __str__(self):
        return f"{self.index:<5}"\
            f"{self.name:<20}"\
            f"{self.type_to_string():<15}"\
            f"0x{self.addr:<20}"\
            f"0x{self.offset.lstrip('0'):<10}"\
            f"0x{self.size.lstrip('0'):<10}"\
            f"{self.flags_to_string():<10}"\
            f"0x{self.info.lstrip('0'):<10}"\
            f"0x{self.link.lstrip('0'):<10}"\
            f"0x{self.align.lstrip('0'):<10}"\
            f"0x{self.size_entry.lstrip('0'):<10}"
