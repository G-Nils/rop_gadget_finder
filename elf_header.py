"""
    Represent an ELF header.
    Note: all fields are strings. They are reversed (little endian) already.
"""


from util import read_bytes


class ELF_HEADER(object):
    def __init__(self, bytes: bytearray):
        self.bytes = bytes
        self.magic = read_bytes(self.bytes, 0, end=4)
        self.cls = read_bytes(self.bytes, 4)
        self.data = read_bytes(self.bytes, 5)
        self.header_version = read_bytes(self.bytes, 6)
        self.os_abi = read_bytes(self.bytes, 7)
        self.padding = read_bytes(self.bytes, 8, end=15)
        self.type = read_bytes(self.bytes, 16, count=2)
        self.instr_set = read_bytes(self.bytes, 18, count=2)
        self.elf_version = read_bytes(self.bytes, 20, count=3)
        self.prog_entry = None
        self.prog_header_table_pos = None
        self.section_header_table_pos = None
        self.flags = None
        self.header_size = None
        self.prog_header_table_entry_size = None
        self.prog_header_table_num_entries = None
        self.section_header_table_entry_size = None
        self.section_header_table_num_entries = None
        self.section_header_string_table_index = None

        # Starting with the program entry point, 32-bit and 64-bit headers are different
        if self.cls == "01":
            self.parse_thirty_two()
        elif self.cls == "02":
            self.parse_sixty_four()

    def parse_thirty_two(self):
        self.prog_entry = read_bytes(self.bytes, 24, end=27)
        self.prog_header_table_pos = read_bytes(self.bytes, 28, end=31)
        self.section_header_table_pos = read_bytes(self.bytes, 32, end=35)
        self.flags = read_bytes(self.bytes, 36, end=39)
        self.header_size = read_bytes(self.bytes, 40, end=41)
        self.prog_header_table_entry_size = read_bytes(self.bytes, 42, end=43)
        self.prog_header_table_num_entries = read_bytes(self.bytes, 44, end=45)
        self.section_header_table_entry_size = read_bytes(
            self.bytes, 46, end=47)
        self.section_header_table_num_entries = read_bytes(
            self.bytes, 48, end=49)
        self.section_header_string_table_index = read_bytes(
            self.bytes, 50, end=51)

    def parse_sixty_four(self):
        self.prog_entry = read_bytes(self.bytes, 24, end=31)
        self.prog_header_table_pos = read_bytes(self.bytes, 32, end=39)
        self.section_header_table_pos = read_bytes(self.bytes, 40, end=47)
        self.flags = read_bytes(self.bytes, 48, end=51)
        self.header_size = read_bytes(self.bytes, 52, end=53)
        self.prog_header_table_entry_size = read_bytes(self.bytes, 54, end=55)
        self.prog_header_table_num_entries = read_bytes(self.bytes, 56, end=57)
        self.section_header_table_entry_size = read_bytes(
            self.bytes, 58, end=59)
        self.section_header_table_num_entries = read_bytes(
            self.bytes, 60, end=61)
        self.section_header_string_table_index = read_bytes(
            self.bytes, 62, end=63)

    def cls_to_string(self) -> str:
        if self.cls == "01":
            return "32-Bit"
        elif self.cls == "02":
            return "64-Bit"
        else:
            return f"Invalid Class (read value: {self.cls})"

    def data_to_string(self) -> str:
        if self.data == "01":
            return "Little Endian"
        elif self.cls == "02":
            return "Big Endian"
        else:
            return f"Invalid Data entry. Could not determine endianess (read value: {self.data})"

    def os_abi_to_string(self) -> str:
        if self.os_abi == "00":
            return "SYSTEM V"
        elif self.os_abi == "01":
            return "HP-UX"
        elif self.os_abi == "02":
            return "NetBSD"
        elif self.os_abi == "03":
            return "Linux"
        elif self.os_abi == "04":
            return "GNU Hurd"
        elif self.os_abi == "06":
            return "Solaris"
        elif self.os_abi == "07":
            return "AIX"
        elif self.os_abi == "08":
            return "IRIX"
        elif self.os_abi == "09":
            return "FreeBSD"
        elif self.os_abi == "0a":
            return "True64"
        elif self.os_abi == "0b":
            return "Novell Modesto"
        elif self.os_abi == "0c":
            return "OpenBSD"
        elif self.os_abi == "0d":
            return "OpenVMS"
        elif self.os_abi == "0e":
            return "SNonStop Kernel"
        elif self.os_abi == "0f":
            return "AROS"
        elif self.os_abi == "10":
            return "Fenix OS"
        elif self.os_abi == "11":
            return "CloudABI"
        elif self.os_abi == "12":
            return "Stratus Technologies OpenVOS"
        else:
            return f"Unknown OS ABI (read value: {self.os_abi})"

    def type_to_string(self) -> str:
        if self.type == "0000":
            return "NONE"
        elif self.type == "0001":
            return "REL (relocatable)"
        elif self.type == "0002":
            return "EXEC (executable)"
        elif self.type == "0003":
            return "DYN (shared object)"
        elif self.type == "0004":
            return "CORE (core dump)"
        elif self.type == "FE00":
            return "LOOS"
        elif self.type == "FEFF":
            return "HIOS"
        elif self.type == "FF00":
            return "LOPROC"
        elif self.type == "FFFF":
            return "HIPROC"
        else:
            return f"Unknown type (read value: {self.type})"

    def instr_set_to_string(self) -> str:
        # Just listing the most common ones here
        if self.instr_set == "0002":
            return "Sparc"
        elif self.instr_set == "0003":
            return "x86"
        elif self.instr_set == "0008":
            return "MIPS"
        elif self.instr_set == "0014":
            return "PowerPC"
        elif self.instr_set == "0028":
            return "ARM"
        elif self.instr_set == "002A":
            return "SuperH"
        elif self.instr_set == "0032":
            return "IA-64"
        elif self.instr_set == "003e":
            return "x86_64"
        elif self.instr_set == "00B7":
            return "AArch64"
        elif self.instr_set == "00F3":
            return "RISC-V"
        else:
            return f"Unknown instruction set type (read value: {self.instr_set}"

    def __str__(self):

        return "ELF Header:\n"\
            f"Magic:                                {bytes.fromhex(self.magic).decode('utf-8')[::-1]}\n"\
            f"Class:                                {self.cls_to_string()}\n"\
            f"Data:                                 {self.data_to_string()}\n"\
            f"Header Version:                       {self.header_version}\n"\
            f"OS ABI:                               {self.os_abi_to_string()}\n"\
            f"Padding:                              {self.padding}\n"\
            f"Type:                                 {self.type_to_string()}\n"\
            f"Inst Set:                             {self.instr_set_to_string()}\n"\
            f"ELF Version:                          {self.elf_version}\n"\
            f"Entry Point:                          0x{self.prog_entry.lstrip('0')}\n"\
            f"Start Program Headers:                0x{self.prog_header_table_pos.lstrip('0')} bytes into file\n"\
            f"Start Section Headers:                0x{self.section_header_table_pos.lstrip('0')} bytes into file\n"\
            f"Flags:                                {self.flags}\n"\
            f"Header Size:                          0x{self.header_size.lstrip('0')} bytes \n"\
            f"Size Program Headers:                 0x{self.prog_header_table_entry_size.lstrip('0')} bytes\n"\
            f"Program Header Entries:               0x{self.prog_header_table_num_entries.lstrip('0')}\n"\
            f"Size Section Headers:                 0x{self.section_header_table_entry_size.lstrip('0')}\n"\
            f"Section Header Entries:               0x{self.section_header_table_num_entries.lstrip('0')}\n"\
            f"Section Header String Table Index:    0x{self.section_header_string_table_index.lstrip('0')}\n"
