"""
    Represent an ELF file. Consists of ELF, program and section headers
"""

from program_header import PROGRAM_HEADER
from elf_header import ELF_HEADER
from section_header import SECTION_HEADER
from util import read_bytes, read_until_nullbyte


class ELF(object):
    prog_header_flags = "R = Read, W = Write, E = Executable"
    section_header_flags = "W = Write, A = Alloc, X = Executabe, M = Merge, S = Strings, I = Info, O = Link Order, N = OS Nonconforming, G = Group, T = TLS"

    def __init__(self, name: str, bytes: bytearray) -> None:
        """
            Initializes the ELF object.
            Raises an ValueError, if the file is not an ELF file
        """
        self.name = name
        self.bytes = bytes
        if not self.is_elf():
            print("[!]: File is not an ELF file")
            raise ValueError("Specified file is not an ELF File")
        self.elf_header = ELF_HEADER(bytes)
        self.program_headers = self.read_program_headers()
        self.section_headers = self.read_section_headers()

    def is_elf(self) -> bool:
        """
            Checks if the specified bytes indicate an ELF file by comparing the first 4 bytes to 0x7f E L F

            Returns:
                bool
                    True, if first four bytes match ELF header, else False
        """
        return self.bytes[0:4] == b"\x7fELF"

    def read_program_headers(self) -> list[PROGRAM_HEADER]:
        """
            Reads all program headers. Offset is taken from the elf header


            Returns:
                list[PROGRAM_HEADER]
                a list of all found program headers. Size can be found beforehand (elf header 'prog_header_table_num_entries')
        """
        program_headers = []
        expected_header_count = int(
            self.elf_header.prog_header_table_num_entries, 16)
        prog_header_size = int(
            self.elf_header.prog_header_table_entry_size, 16)
        prog_header_start = int(self.elf_header.prog_header_table_pos, 16)

        for i in range(0, expected_header_count):
            start = prog_header_start + i * prog_header_size
            end = start + prog_header_size

            program_headers.append(
                PROGRAM_HEADER(self.bytes[start:end], i, self.elf_header.cls == "01"))

        return program_headers

    def read_section_headers(self) -> list[SECTION_HEADER]:
        """
        Reads all section headers. Offset is taken from the elf header


        Returns:
            list[SECTION_HEADER]
                a list of all found program headers. Size can be found beforehand (elf header 'section_header_table_num_entries')
        """
        section_headers: list[SECTION_HEADER] = []
        expected_header_count = int(
            self.elf_header.section_header_table_num_entries, 16)
        section_header_size = int(
            self.elf_header.section_header_table_entry_size, 16)
        section_header_start = int(
            self.elf_header.section_header_table_pos, 16)

        for i in range(0, expected_header_count):
            start = section_header_start + i * section_header_size
            end = start + section_header_size
            section_headers.append(
                SECTION_HEADER(self.bytes[start:end], i, self.elf_header.cls == "01"))

        """
            Add the names to the sections
            First find the string table section (index: 'section_header_string_table_index' in the elf header)
            Calculated address by using the shstrab offset and the individuel section offset
            Read name until NULL Byte
            Turn bytes into utf-8 string

        """
        shstrab = section_headers[int(
            self.elf_header.section_header_string_table_index, 16)]
        for sh in section_headers:
            string_table_offset = int(sh.name_offset, 16)
            start = int(shstrab.offset, 16) + string_table_offset
            name = read_until_nullbyte(self.bytes, start)
            sh.name = bytes.fromhex(name).decode('utf-8')[::-1]

        return section_headers

    """ Getter utilities """

    def get_section_by_flag(self, flag: str) -> list[SECTION_HEADER]:
        sections = [
            sh for sh in self.section_headers if flag in sh.flags_to_string()]
        #"W = Write, A = Alloc, X = Executabe, M = Merge, S = Strings, I = Info, O = Link Order, N = OS Nonconforming, G = Group, T = TLS"
        return sections

    def get_section_by_index(self, index: int) -> SECTION_HEADER:
        match = [sh for sh in self.section_headers if sh.index == index]
        if len(match) > 0:
            return match[0]
        else:
            return None

    def read_at_address(self, address: int, read_count: int) -> str:
        """
            Reads read_count bytes from a specified virtual address

            Parameters:
                address: int
                    The address to read from
                read_count : int
                    The amount of bytes to read


            Returns:
                str
                    String of hex bytes. bytes[address] is the last one in the returned string
        """
        # use the first segment as a base address for virutal address calculation
        first_section = self.get_section_by_index(
            1)
        base_calc_addr = int(first_section.addr, 16)
        diff = address - base_calc_addr
        return read_bytes(self.bytes, int(first_section.offset, 16) + diff, count=read_count)

    def read_opcodes(self, address: int, size) -> list[str]:
        """
            Reads opcodes from a specified virtual address

            Parameters:
                address: int
                    The address to read from
                size : int
                    The amount of bytes to read. Generally you would want to specify the amount of opcodes which form the expected instruction


            Returns:
                list[str]
                    String of hex bytes opcodes
        """
        bytes = self.read_at_address(address, size)
        codes = [bytes[i:i+2] for i in range(0, len(bytes), 2)]
        return codes[::-1]

    """Printing utilities """

    def print_elf_header(self):
        print(f"{self.elf_header}")

    def print_program_headers(self):
        program_headers = [f"{str(ph)}\n" for ph in self.program_headers]
        print("Program Headers:\n"
              f"Type{'':<15}Address(virt){'':<10}Address(phy){'':<10}Offset{'':<8}Size(file){'':<7}Size(mem){'':<5}Flags{'':<5}Align\n"
              f"{''.join(program_headers)}\n"
              f"{self.prog_header_flags}\n\n\n")

    def print_section_headers(self):
        section_headers = [f"{str(sh)}\n" for sh in self.section_headers]
        print("Section Headers: \n"
              f"ID{'':<5}Name{'':<15}Type{'':<15}Address{'':<10}Offset{'':<5}Size{'':<5}Flags{'':<8}Info{'':<8}Link{'':<7}Align{'':<5}Entr. Size{'':<5}\n"
              f"{''.join(section_headers)}\n"
              f"{self.section_header_flags}\n\n\n")

    def __str__(self):
        program_headers = [f"{str(ph)}\n" for ph in self.program_headers]
        section_headers = [f"{str(sh)}\n" for sh in self.section_headers]
        return f"{self.elf_header}\n\n"\
            "Program Headers:\n"\
            f"Type{'':<15}Address(virt){'':<10}Address(phy){'':<10}Offset{'':<8}Size(file){'':<7}Size(mem){'':<5}Flags{'':<5}Align\n"\
            f"{''.join(program_headers)}\n"\
            f"{self.prog_header_flags}\n\n\n"\
            "Section Headers: \n"\
            f"ID{'':<5}Name{'':<15}Type{'':<15}Address{'':<10}Offset{'':<5}Size{'':<5}Flags{'':<8}Info{'':<8}Link{'':<7}Align{'':<5}Entr. Size{'':<5}\n"\
            f"{''.join(section_headers)}\n"\
            f"{self.section_header_flags}\n\n\n"

    """ static """
    def from_file(file: str):
        """
            Creates an ELF object from an ELF file

            Returns:
                ELF
                an ELF object containing the bytes in the file
        """
        with open(file, "rb") as elf_file:
            bytes = bytearray(elf_file.read())

        return ELF(file, bytes)
