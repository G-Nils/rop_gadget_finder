"""
    Contains utilities for reading bytes into hex strings
"""


def read_bytes(all_bytes: bytearray, start, end=0, count=0) -> str:
    """
        Reads a certain amount of bytes from a given bytearray.

        Parameters:
            all_bytes: bytearray
                The bytearray of all the bytes
            start : int
                Start address to read from (all_bytes[start] is included in the output)
            end : int (default=0)
                End address to read to (all_bytes[end] is *NOT* included in the output)
            count : int
                Amount of bytes to read. (all_bytes[start+count] is *NOT* included in the output))

        Returns:
            str
                Returns the read bytes as a hexadecimal string in *REVERSED* order
                If start, end or start+count are arger than the length of all_bytes, return all_bytes as a hexadecimal string in *REVERSED* order
    """
    if start > len(all_bytes) or end > len(all_bytes) or start+count > len(all_bytes):
        print("[!] Index too large. Returning all bytes")
        return all_bytes[::-1].hex()

    if end == 0 and count == 0:
        end = start+1

    if end != 0:
        return all_bytes[start:end][::-1].hex()

    if count != 0:
        return all_bytes[start:start+count][::-1].hex()

    return all_bytes[::-1].hex()


def read_until_nullbyte(all_bytes: bytearray, start):
    """
        Reads from a given bytearray, starting from an index, until a NULL byte was found

        Parameters:
            all_bytes: bytearray
                The bytearray of all the bytes
            start : int
                Start address to read from (all_bytes[start] is included in the output)

        Returns:
            str
                Returns the read bytes as a hexadecimal string in *REVERSED* order
                If start is larger than the length of all_bytes, return all_bytes as a hexadecimal string in *REVERSED* order
    """
    read_bytes: bytearray = []
    if start > len(all_bytes):
        print("[!] Index too large. Returning all bytes")
        return all_bytes[::-1].hex()

    for b in all_bytes[start:]:
        if b == 0:
            return bytearray(read_bytes)[::-1].hex()
        else:
            read_bytes.append(b)
