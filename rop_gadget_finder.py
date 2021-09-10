#!/usr/bin/python3

"""
    A simple tool to find rop gadgets within linux ELF files

    Uses hinting, so we need Python 3.5+
    Requires:
        - argparse 
        - capstone
        - twelfe 

    Example:
        python3 rop_gadget_finder.py -e test --gadget "pop rbp"

"""
import argparse
from typing import Any
from elf import *
from capstone import *

# Gadgets have to end in one of these instructions.
# Can be edited to seach for more, e.g conditional jumps (e.g. 'je')
gadget_to_search_for = ["ret", "call", "jmp"]


class Gadget(object):
    def __init__(self, address: int, instructions: list[CsInsn]):
        """
            Applies the filter and outputs the gadgets in the specified way

            Parameters:
                address : int
                    Address of the gadget instruction (ret/call/jmp)

                instructions: list[CsInsn]
                    List of  decoded instructions (CSInsn)
        """
        self.address = address
        self.instructions = instructions

    def __str__(self) -> str:
        str = []
        for i in self.instructions:
            str.append(format(f"{hex(i.address)}\t{i.mnemonic}\t{i.op_str}"))
        return "\n".join(str)

    def __eq__(self, other) -> bool:
        """
            Implements the comparison between two gadgets ('==').
            Two gadgets are equal, if all their instructions match (mnemonic, op_str and address)
        """
        if self.address != other.address:
            return False

        for i, inst in enumerate(self.instructions):
            if self.instructions[i].mnemonic != other.instructions[i].mnemonic:
                return False
            if self.instructions[i].op_str != other.instructions[i].op_str:
                return False
            if self.instructions[i].address != other.instructions[i].address:
                return False

        return True

    def __lt__(self, other) -> bool:
        """
            Implements less than (<) for gadgets.
            One gadget is 'less than' another one, if its instructions are a subset of 'others' instructions.
            Checks if selfs instructions are a subset of others instruction:
            This example should return true:
            self:
            0x4011e8        add     rsp, 8
            0x4011ec        ret

            other:
            0x4011e5        sub     esp, 8
            0x4011e8        add     rsp, 8
            0x4011ec        ret


        """

        if self.address != other.address:
            return False

        if self == other:
            return False

        # Searches for first matching instruction and then searching for follwing matching instructions from there
        in_other = True
        instr_match_index = 0
        for i, instr in enumerate(self.instructions):
            for other_instr in other.instructions[instr_match_index:]:
                if self._instr_equal(instr, other_instr):
                    instr_match_index = i
                    break
            in_other = False

        return in_other

    def split_gadget(self):
        """
            Splits a gadget with two gadget instructions into two gadgets

            Returns:
                list[Gadget] 
                    A list of the two gadgets which results from splitting, one of them is 'self'.

            Note: changes self.instructions.

        """
        if self._gadget_instr_count() <= 1:
            return [self]
        if self._gadget_instr_count() == 1:
            return [self]

        # Search for the splitting point (aka the first gadget instruction)
        first_gadget_index = 0
        for i, instr in enumerate(self.instructions):
            if instr.mnemonic in gadget_to_search_for:
                first_gadget_index = i
                break

        new_gadget_instructions = self.instructions[:first_gadget_index+1]
        new_gadget_address = self.instructions[first_gadget_index]

        self.instructions = self.instructions[first_gadget_index+1::]
        return [self, Gadget(new_gadget_address, new_gadget_instructions)]

    def _instr_equal(self, i1, i2) -> bool:
        """
            Two instructions are equal if their mnemonic, their op_str and their address match
        """
        return i1.mnemonic == i2.mnemonic and i1.op_str == i2.op_str and i1.address == i2.address

    def _gadget_instr_count(self) -> int:
        """
            Counts the number of gadget instructions within this gadget

            Returns:
                int 
                    the number of gadget instructions within this gadget

        """
        count = 0
        for instr in self.instructions:
            if instr.mnemonic in gadget_to_search_for:
                count += 1

        return count


def dump_asm(elf) -> list[str]:
    """ 
        Counts the number of gadget instructions within this gadget

        Parameters:
            elf : elf.ELF
                The ELF file in which to find gadgets

        Returns:
            list[list[CsInsn]]
                A list of lists of CsInsns. Sounds more complicated than it is. It's pretty much just a list of assembly instructions

        """
    assembly = []
    exec_sections = elf.get_section_by_flag("X")  # get all executable sections

    for es in exec_sections:
        start_addr = int(es.addr, 16)
        print(
            f"Searching in section: {es.name}: {hex(start_addr)} - {hex(start_addr + int(es.size, 16))}")

        # We want to find 'hidden' gadgets, which means we do decode with variable offsets and length
        # Length of maximum 20 has shown in testing to be sufficient enough
        for offset in range(int(es.size, 16)):
            for i in range(20):
                opcode = elf.read_opcodes(start_addr+offset, i)

                assembly.append(decode_opcodes(
                    prepare_opcocde("".join(opcode)), start_addr+offset))

    return assembly


def prepare_opcocde(opcode_str: str) -> bytes:
    """
        Turns the opcode into the format capstones need for decoding

        Parameters:
            opcode_str : str
                The string which represents the opcode in hex form, e. g. '8d3dc4'

        Returns:
            bytes
                A byte string for captsone to decode in form like : "b'\\x8d\\x3d\\xc4"
    """
    return bytes.fromhex(opcode_str)


def decode_opcodes(code: bytes, address: int) -> list[CsInsn]:
    """
        Decodes the given bytes to intel assembly instructions

        Parameters:
            code : bytes
                A byte string for captsone to decode in form like : "b'\\x8d\\x3d\\xc4"

        Returns:
            list[CsInsn]
                List of CsInsn instructions.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    return list(md.disasm(code, address))


def find_gadgets(assembly: list[list[CsInsn]]) -> list[Gadget]:
    """
        Find rop gadgets within the list of given instructions

        Parameters:
            assembly : list[list[CsInsn]]
                List of different list of CsInsn instructions. Each inner list represents one 'decoding operation'.

        Returns:
            list[Gadget]
                List of usable rop gadgets.
    """
    gadgets = []

    # type of ams is list[CsInsn]
    for asm in assembly:
        # Remove all single instruction gadgets
        if len(asm) <= 1:
            continue

        # Make sure the last instruction in asm is a gadget instruction
        last_instr = asm[len(asm)-1]
        last_instr_mnem = last_instr.mnemonic
        if not last_instr_mnem in gadget_to_search_for:
            continue

        # Found a valid gadget to add
        x = Gadget(last_instr.address, asm)
        gadgets.append(x)

    """
        Filter out smaller gadget e.g:
        
        1 pop rbp
        2 ret

        is already in 

        1 pop rax
        2 pop rbp
        3 ret

        Also: The way we generate instructions from opcode, we might have "gadgets" than contains two gadget instructions
        So we have to split them into two gadgets
        TODO: looks really ugly, there is probably a more pythonic way to do this
    """
    final_gadgets = []
    keep = True
    for g1 in gadgets:
        keep = True
        for g2 in gadgets:
            if g1 is g2:
                continue
            if g1 < g2 or g1 == g2:
                keep = False
                continue
        if keep:
            if g1._gadget_instr_count() > 1:
                splitted = g1.split_gadget()
                final_gadgets.extend(splitted)
            else:
                final_gadgets.append(g1)

    return final_gadgets


def output_results(gadgets, write_to_file, outfile, format, gadget_filter, size=0) -> None:
    """
        Applies the filter and outputs the gadgets in the specified way

        Parameters:
            gadgets : list[Gadget]
                The list of all find gadgets

            write_to_file: bool
                Specifies whether the output should be written to a file

            outfile: str
                Path of the output file

            format: str
                Specifies the format, should be either 'c' or 'g'

            gadget_filter: str
                A keyword to search for in the gadgets, e.g. a register name like rsi

            size: int
                Amount of instruction before the gadget instruction (ret/call/jmp)
    """

    # Slice gadgets to the given size
    if size > 0:
        for gadget in gadgets:
            if len(gadget.instructions) > size:
                gadget.instructions = gadget.instructions[-size-1:]

    # Apply the -g/--gadget filter
    result_gadgets = []
    if gadget_filter != "":
        for gadget in gadgets:
            for inst in gadget.instructions:
                instr_string = inst.mnemonic + " " + inst.op_str
                if "".join(instr_string).find(gadget_filter) > 0 or gadget_filter in instr_string:
                    result_gadgets.append(gadget)
    else:
        result_gadgets = gadgets

    # Write to file or print to screen, applying the grepable format if specified
    if write_to_file:
        with open(outfile, "w+") as outfile:
            for gadget in result_gadgets:
                outfile.write(str(gadget) + "\n\n")
    else:
        if format == "g":
            for gadget in result_gadgets:
                s = ""
                for instr in gadget.instructions:
                    s += str(instr)
                print(f"{s}", end="")
        else:
            for gadget in result_gadgets:
                print(f"{str(gadget)}\n")

    print(f"\nFound {len(result_gadgets)} gadgets\n")


def main() -> None:
    """
        Main Entry. Validates the passed arguments.

    """

    args = read_args()
    executable = args["executable"]
    try:
        size = int(args["size"])
    except ValueError:
        print(f"Specified size {args['size']} is not a valid integer")
        return

    outfile = args["output"]
    write_to_file = True if outfile != "" else False
    outformat = args["format"]
    gadget_filter = args["gadget"]

    if executable == "":
        print("[!] Missing executable name")
        return

    if size < 0:
        print(f"[!]Invalid size {size}")
        return

    if size > 10:
        print(
            f"[!] Size {size} is quite large. Might lead to unreasonable results")

    if outformat not in ["g", "s"]:
        print(f"[!] Invalid output format {outformat}")
        return

    print(
        f"Starting rop_gadget_finder with following parameters:\n"
        f"Executable:       \t{executable}\n"
        f"Size:             \t{size}\n"
        f"Writing to file:  \t{write_to_file} ({outfile})\n"
        f"Output format:    \t{outformat}\n"
    )

    elf = ELF.from_file(executable)  # read the elf file
    assembly = dump_asm(elf)  # decodes opcodes to instructions
    gadgets = find_gadgets(assembly)  # find gadgets in instructions

    # Output the results while applying search and output filter
    output_results(gadgets, write_to_file, outfile,
                   outformat, gadget_filter, size)


def read_args() -> dict[str, Any]:
    """
        Creates the argparse argument parser

        Returns:
            dict[str, Any]
                The dictionary of read command line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--executable",
                        help="Path to executable", required=True, default="")
    parser.add_argument("-s", "--size",
                        help="Amount of instructions before a 'ret' (default=3)", default=3)
    parser.add_argument(
        "-o", "--output", help="Path to output file", required=False, default="")
    parser.add_argument(
        "-f", "--format", help="Output format (g(reppable), s(tandard)). (default = s)", required=False, default="s")
    parser.add_argument(
        "-g", "--gadget", help="Search term to filter for (e.g. pop rbp)", required=False, default="")
    return vars(parser.parse_args())


if __name__ == "__main__":
    main()
