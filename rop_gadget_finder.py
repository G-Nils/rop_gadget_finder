# /usr/bin/python3
import argparse
from os import ttyname
from typing import Any
from elf import *
from capstone import *


class Gadget(object):
    def __init__(self, address, instructions):
        self.address = address
        self.instructions = instructions

    def __str__(self) -> str:
        str = []
        for i in self.instructions:
            str.append(format(f"{hex(i.address)}\t{i.mnemonic}\t{i.op_str}"))
        return "\n".join(str)

    def __eq__(self, other) -> bool:
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

    def __gt__(self, other):
        return not self < other and not self == other

    def __lt__(self, other) -> bool:
        """
            Checks if selfs instructions are a subset of others instruction:
            For example:
            self:
            0x4011e8        add     rsp, 8
            0x4011ec        ret

            other:
            0x4011e5        sub     esp, 8
            0x4011e8        add     rsp, 8
            0x4011ec        ret

            should return true
        """

        if self.address != other.address:
            return False

        if self == other:
            return False

        in_other = True
        instr_match_index = 0
        for i, instr in enumerate(self.instructions):
            for other_instr in other.instructions[instr_match_index:]:

                if self._instr_equal(instr, other_instr):
                    instr_match_index = i
                    break
            in_other = False

        if in_other:
            pass
        return in_other

    def split_gadget(self):
        if self._gadget_instr_count == 1:
            return [self]

        gadgets = []
        gadget_to_search_for = ["ret", "call", "jmp"]
        first_gadget_index = 0
        for i, instr in enumerate(self.instructions):
            if instr.mnemonic in gadget_to_search_for:
                first_gadget_index = i
                break

        new_gadget_instructions = self.instructions[:first_gadget_index+1]
        new_gadget_address = self.instructions[first_gadget_index]

        self.instructions = self.instructions[first_gadget_index+1::]
        return [self, Gadget(new_gadget_address, new_gadget_instructions)]

    def _instr_equal(self, i1, i2):
        return i1.mnemonic == i2.mnemonic and i1.op_str == i2.op_str and i1.address == i2.address

    def _gadget_instr_count(self):
        count = 0
        gadget_to_search_for = ["ret", "call", "jmp"]
        for instr in self.instructions:
            if instr.mnemonic in gadget_to_search_for:
                count += 1

        return count


def dump_asm(elf, size) -> list[str]:
    assembly = []
    exec_sections = elf.get_section_by_flag("X")

    for es in exec_sections:
        print(f"Searching in section: {es.name}")
        start_addr = int(es.addr, 16)
        print(f"Searching in section: {es.addr}")
        end = start_addr + int(es.size, 16)
        for offset in range(int(es.size, 16)):

            for i in range(20):
                opcode = elf.read_opcodes(start_addr+offset, i)

                assembly.append(decode_opcodes(
                    prepare_opcocde("".join(opcode)), start_addr+offset))

    return assembly


def prepare_opcocde(opcode_str: str):
    return bytes.fromhex(opcode_str)


def decode_opcodes(code, address):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instr = []
    for i in md.disasm(code, address):
        instr.append(i)

    return instr


def find_gadgets(assembly, size):
    gadgets = []
    gadget_to_search_for = ["ret", "call", "jmp"]
    for asm in assembly:
        # Remove all single instruction gadgets
        if len(asm) <= 1:
            continue
        last_instr = asm[len(asm)-1]
        last_instr_mnem = last_instr.mnemonic

        if not last_instr_mnem in gadget_to_search_for:
            continue
        add_gadget = True
        for gadget in gadgets:

            x = Gadget(last_instr.address, asm)

            is_less = x < gadget

        if add_gadget:
            x = Gadget(last_instr.address, asm)
            gadgets.append(x)

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
        f"Starting ropper_dump with following paramters:\n"
        f"Executable:       \t{executable}\n"
        f"Size:             \t{size}\n"
        f"Writing to file:  \t{write_to_file} ({outfile})\n"
        f"Output format:    \t{outformat}\n"
    )

    elf = ELF.from_file(executable)
    assembly = dump_asm(elf, size)

    # decode_opcodes(CODE)
    # decode_opcodes(prepare_opcocde(CODE2))
    gadgets = find_gadgets(assembly, size)
    for gadget in gadgets:
        print(f"{gadget}\n")
        # pass

    print(f"Found {len(gadgets)} gadgets")
    # output_results(gadgets, write_to_file, outfile, outformat, gadget_filter)


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
        "-f", "--format", help="Output format (g(reppable, s(tandard)))", required=False, default="s")
    parser.add_argument(
        "-g", "--gadget", help="Search term to filter for (e.g. eax)", required=False, default="")
    return vars(parser.parse_args())


if __name__ == "__main__":
    main()
