import idc
import idautils
import idaapi

from datetime import datetime
import math
import string

# global variables (in python u dont really need to declare them, but just for clarifying)

# user input

dry_run = False
verbose = False

FirstSegment_VirtualAddress = 0x00000000

SegmentBeforeMemHole_VirtualAddress = 0x00000000

SegmentAfterMemHole_Unmapped_VirtualAddress = 0x00000000
SegmentAfterMemHole_Mapped_VirtualAddress = 0x00000000
SegmentAfterMemHole_FileSize = 0x00000000
SegmentAfterMemHole_MemorySize = 0x00000000

# program input

BytesLength = 2
SizesLength = 8
AddressesLength = 8

# 000x: 0 - overwrite the sequence bytes offset if it's empty
#       1 - overwrite the sequence bytes offset even if it's not empty
# 00x0: 0 - do not overwrite using the suggested sequence bytes offset
#       1 - overwrite using the suggested sequence bytes offset if it's not empty
# 0x00: 0 - do not overwrite using the suggested hardcore sequence bytes offset
#       1 - overwrite using the suggested hardcore sequence bytes offset if it's not empty
# x000: 0 - prioritize suggested sequence bytes offset over suggested hardcore sequence bytes offset
#       1 - prioritize suggested hardcore sequence bytes offset over suggested sequence bytes offset

sequence_bytes_offset_use_options = int("0000", 2)

# program variables (shouldn't be changed in most cases)

successes = 0
failures = 0

patched_bytes = 0

first_segment_to_segment_before_memhole_matches = 0
segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches = 0

head = None

cmd = None
cmd_length = None
cmd_fixed = None
cmd_fixed_length = None
cmd_fixed_splitted = None
cmd_fixed_splitted_amount = None
cmd_fixed_splitted_index = None
cmd_fixed_splitted_cell = None
cmd_fixed_splitted_cell_length = None
cmd_fixed_splitted_cell_index = None

static_TP_text = "static_TP"
static_TP_text_length = len(static_TP_text)

cs_text = "cs:"  # code segment
cs_text_length = len(cs_text)

SegmentIndex = None

exception_text = None

mem_hole_size = SegmentAfterMemHole_Unmapped_VirtualAddress - SegmentAfterMemHole_Mapped_VirtualAddress

min_bytes_size = int(mem_hole_size)
min_bytes_amount = int(math.ceil(math.log(min_bytes_size, 0x100)))
min_bytes_estimated_amount = int(math.pow(2, int(math.ceil(math.log(min_bytes_amount, 2)))))
min_bytes_index = None
min_byte = None

max_bytes_size = (
    int(math.pow(0x100, int(math.ceil(
        math.log(
            (SegmentAfterMemHole_Unmapped_VirtualAddress + SegmentAfterMemHole_MemorySize - 1) * 1.2, 0x100
        )  # multiplying by 1.2 because the hex bytes might be a big bigger than the last address, so doing it in order to stay on the safe zone
    )))) - 1
)  # for example, if its 0x500, it gets multiplied by 1.2 to 0x600, which is 2 bytes, so it goes to 0xFFFF which is the max number in 2 bytes

max_bytes_amount = int(math.ceil(math.log(max_bytes_size, 0x100)))
max_bytes_estimated_amount = int(math.pow(2, int(math.ceil(math.log(max_bytes_amount, 2)))))
max_bytes_index = None
max_byte = None

sequence_bytes = None
sequence_bytes_address = None
sequence_bytes_original_amount = None
sequence_bytes_amount = None
sequence_bytes_offset = None
sequence_bytes_index = None
sequence_byte = None

suggested_sequence_bytes_offset = None
suggested_sequence_bytes_offset_matches = 0
suggested_sequence_bytes_offset_mismatches = 0

# suggested hardcore is digging hard, not 100% safe
# , you can still use it without having the suggested sequence bytes offset use set as to use it, and use dry run to see the suggested ones

suggested_hardcore_sequence_bytes_offset = None
suggested_hardcore_sequence_bytes_offset_matches = 0
suggested_hardcore_sequence_bytes_offset_mismatches = 0

original_bytes = None
original_bytes_address = None
original_bytes_size = None
original_bytes_amount = None
original_bytes_index = None
original_byte = None

fixed_bytes = None
fixed_bytes_address = None
fixed_bytes_size = None
fixed_bytes_amount = None
fixed_bytes_index = None
fixed_byte = None


def WaitForInitialAutoanalysis():
    idc.auto_wait()


def CheckHeads(start_address, end_address):  # returns the heads in the range
    result = idautils.Heads(start_address, end_address)

    return result


def CheckCommand(address):  # returns the command
    result = str(idc.GetDisasm(address))

    return result


def CheckHexText(source, length, add_0x):  # returns the hex text
    source_hex = str(hex(source)[2:])
    source_hex_length = len(source_hex)
    source_hex_index = None
    source_hex_cell = None

    for source_hex_index in range(0, source_hex_length):
        source_hex_cell = source_hex[source_hex_index]

        if (source_hex_cell in string.hexdigits) is False:
            source_hex = source_hex[:source_hex_index]

            break

    result = str(source_hex.zfill(length))

    if add_0x is True:
        result = "0x" + result

    return result


def CheckByte(address):  # returns the byte
    result = int(idc.GetOriginalByte(address))

    return result


def ApplyByte(address, byte):
    idc.PatchByte(address, byte)


def CreateSequence(address, amount):
    # if the amount is None then checking the sequence amount using the idc.itemSize function, returns True if succeed to create the sequence, False if didn't

    result = None

    # Global Variables

    # global dry_run
    # global verbose

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_FileSize
    # global SegmentAfterMemHole_MemorySize

    global BytesLength
    global SizesLength
    global AddressesLength

    # global sequence_bytes_offset_use_options

    # global successes
    # global failures

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches
    # global segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches

    # global head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global static_TP_text
    # global static_TP_text_length

    # global cs_text
    # global cs_text_length

    # global SegmentIndex

    # global exception_text

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount
    # global min_bytes_index
    # global min_byte

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount
    # global max_bytes_index
    # global max_byte

    global sequence_bytes
    global sequence_bytes_address
    global sequence_bytes_original_amount
    global sequence_bytes_amount
    global sequence_bytes_offset
    global sequence_bytes_index
    global sequence_byte

    # global suggested_sequence_bytes_offset
    # global suggested_sequence_bytes_offset_matches
    # global suggested_sequence_bytes_offset_mismatches

    # global suggested_hardcore_sequence_bytes_offset
    # global suggested_hardcore_sequence_bytes_offset_matches
    # global suggested_hardcore_sequence_bytes_offset_mismatches

    # global original_bytes
    # global original_bytes_address
    # global original_bytes_size
    # global original_bytes_amount
    # global original_bytes_index
    # global original_byte

    # global fixed_bytes
    # global fixed_bytes_address
    # global fixed_bytes_size
    # global fixed_bytes_amount
    # global fixed_bytes_index
    # global fixed_byte

    # Function Variables

    method_found = False

    # Start

    if sequence_bytes_address == address and sequence_bytes_original_amount == amount:
        method_found = True
    else:
        sequence_bytes_original_amount = amount

        sequence_bytes = None
        sequence_bytes_address = address
        sequence_bytes_amount = None
        sequence_bytes_offset = None
        sequence_bytes_index = None
        sequence_byte = None

        if sequence_bytes_original_amount is not None:
            sequence_bytes_amount = sequence_bytes_original_amount
        else:
            sequence_bytes_amount = int(idc.ItemSize(sequence_bytes_address))

        # print(str(sequence_bytes_amount))

        if sequence_bytes_amount is not None and sequence_bytes_amount > 0:
            sequence_bytes = []

            for sequence_bytes_index in range(0, sequence_bytes_amount):
                sequence_byte = None

                sequence_bytes.append(sequence_byte)

            method_found = True

    result = method_found

    return result


def CheckSequenceByte(offset):  # offset from start (0 goes for first cell, 1 for second, etc), returns the sequence byte
    result = None

    # Global Variables

    # global dry_run
    # global verbose

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_FileSize
    # global SegmentAfterMemHole_MemorySize

    global BytesLength
    global SizesLength
    global AddressesLength

    # global sequence_bytes_offset_use_options

    # global successes
    # global failures

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches
    # global segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches

    # global head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global static_TP_text
    # global static_TP_text_length

    # global cs_text
    # global cs_text_length

    # global SegmentIndex

    # global exception_text

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount
    # global min_bytes_index
    # global min_byte

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount
    # global max_bytes_index
    # global max_byte

    global sequence_bytes
    global sequence_bytes_address
    # global sequence_bytes_original_amount
    global sequence_bytes_amount
    # global sequence_bytes_offset
    # global sequence_bytes_index
    global sequence_byte

    # global suggested_sequence_bytes_offset
    # global suggested_sequence_bytes_offset_matches
    # global suggested_sequence_bytes_offset_mismatches

    # global suggested_hardcore_sequence_bytes_offset
    # global suggested_hardcore_sequence_bytes_offset_matches
    # global suggested_hardcore_sequence_bytes_offset_mismatches

    # global original_bytes
    # global original_bytes_address
    # global original_bytes_size
    # global original_bytes_amount
    # global original_bytes_index
    # global original_byte

    # global fixed_bytes
    # global fixed_bytes_address
    # global fixed_bytes_size
    # global fixed_bytes_amount
    # global fixed_bytes_index
    # global fixed_byte

    # Start

    sequence_byte = None

    if offset >= 0 and offset < sequence_bytes_amount:
        if sequence_bytes[offset] is not None:
            sequence_byte = sequence_bytes[offset]
        else:
            sequence_byte = CheckByte(sequence_bytes_address + offset)

            sequence_bytes[offset] = sequence_byte

    result = sequence_byte

    return result


def CheckSequenceBytes(offset, amount, min_size, max_size):
    # set min or max as 0 or below in order to have them disabled, returns True if the original bytes size is in range, False if it isn't

    result = None

    # Global Variables

    # global dry_run
    # global verbose

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_FileSize
    # global SegmentAfterMemHole_MemorySize

    global BytesLength
    global SizesLength
    global AddressesLength

    # global sequence_bytes_offset_use_options

    # global successes
    # global failures

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches
    # global segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches

    # global head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global static_TP_text
    # global static_TP_text_length

    # global cs_text
    # global cs_text_length

    # global SegmentIndex

    # global exception_text

    # global mem_hole_size

    global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount
    # global min_bytes_index
    # global min_byte

    global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount
    # global max_bytes_index
    # global max_byte

    # global sequence_bytes
    global sequence_bytes_address
    # global sequence_bytes_original_amount
    global sequence_bytes_amount
    # global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    # global suggested_sequence_bytes_offset
    # global suggested_sequence_bytes_offset_matches
    # global suggested_sequence_bytes_offset_mismatches

    # global suggested_hardcore_sequence_bytes_offset
    # global suggested_hardcore_sequence_bytes_offset_matches
    # global suggested_hardcore_sequence_bytes_offset_mismatches

    global original_bytes
    global original_bytes_address
    global original_bytes_size
    global original_bytes_amount
    global original_bytes_index
    global original_byte

    # global fixed_bytes
    # global fixed_bytes_address
    # global fixed_bytes_size
    # global fixed_bytes_amount
    # global fixed_bytes_index
    # global fixed_byte

    # Function Variables

    bytes_power = None

    current_min_bytes_size = None

    current_max_bytes_size = None

    method_found = False

    # Start

    if offset >= 0 and offset < sequence_bytes_amount:
        original_bytes = []
        original_bytes_address = sequence_bytes_address + offset
        original_bytes_size = 0
        original_bytes_amount = amount
        original_bytes_index = None
        original_byte = None

        # print(CheckHexText(original_bytes_address, AddressesLength, True))

        for original_bytes_index in range(0, original_bytes_amount):
            bytes_power = int(math.pow(0x00000100, original_bytes_index))

            original_byte = CheckSequenceByte(offset + original_bytes_index)

            if original_byte is not None:
                original_bytes.append(original_byte)

                original_bytes_size += original_byte * bytes_power

                # print(CheckHexText(original_byte, BytesLength, True))
            else:
                break

        # print(CheckHexText(original_bytes_size, SizesLength, True))

        if min_size <= 0:
            current_min_bytes_size = min_bytes_size
        else:
            if min_size < min_bytes_size:
                current_min_bytes_size = min_bytes_size
            else:
                current_min_bytes_size = min_size

        if max_size <= 0:
            current_max_bytes_size = max_bytes_size
        else:
            if max_size > max_bytes_size:
                current_max_bytes_size = max_bytes_size
            else:
                current_max_bytes_size = max_size

        if original_bytes_size >= current_min_bytes_size:
            if original_bytes_size <= current_max_bytes_size:
                method_found = True

    result = method_found

    return result


def PatchSequenceByte(offset, value):  # returns True if succeed to patch the sequence byte, False if failed
    result = False

    # Global Variables

    global dry_run
    # global verbose

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_FileSize
    # global SegmentAfterMemHole_MemorySize

    global BytesLength
    global SizesLength
    global AddressesLength

    # global sequence_bytes_offset_use_options

    # global successes
    # global failures

    global patched_bytes

    # global first_segment_to_segment_before_memhole_matches
    # global segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches

    # global head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global static_TP_text
    # global static_TP_text_length

    # global cs_text
    # global cs_text_length

    # global SegmentIndex

    # global exception_text

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount
    # global min_bytes_index
    # global min_byte

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount
    # global max_bytes_index
    # global max_byte

    global sequence_bytes
    global sequence_bytes_address
    # global sequence_bytes_original_amount
    global sequence_bytes_amount
    # global sequence_bytes_offset
    # global sequence_bytes_index
    global sequence_byte

    # global suggested_sequence_bytes_offset
    # global suggested_sequence_bytes_offset_matches
    # global suggested_sequence_bytes_offset_mismatches

    # global suggested_hardcore_sequence_bytes_offset
    # global suggested_hardcore_sequence_bytes_offset_matches
    # global suggested_hardcore_sequence_bytes_offset_mismatches

    # global original_bytes
    # global original_bytes_address
    # global original_bytes_size
    # global original_bytes_amount
    # global original_bytes_index
    # global original_byte

    # global fixed_bytes
    # global fixed_bytes_address
    # global fixed_bytes_size
    # global fixed_bytes_amount
    # global fixed_bytes_index
    # global fixed_byte

    # Function Variables

    current_result = False

    method_found = False

    # Start

    if offset >= 0 and offset < sequence_bytes_amount:
        current_result = True

        sequence_byte = value

        if sequence_bytes[offset] is not None:
            if sequence_bytes[offset] != sequence_byte:
                method_found = True
        else:
            method_found = True

        if method_found is True:
            sequence_bytes[offset] = sequence_byte

            if dry_run is False:
                ApplyByte(sequence_bytes_address + offset, sequence_byte)

            patched_bytes += 1

    result = current_result

    return result


def PatchSequenceBytes():
    # Global Variables

    # global dry_run
    # global verbose

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_FileSize
    # global SegmentAfterMemHole_MemorySize

    global BytesLength
    global SizesLength
    global AddressesLength

    # global sequence_bytes_offset_use_options

    # global successes
    # global failures

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches
    # global segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches

    # global head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global static_TP_text
    # global static_TP_text_length

    # global cs_text
    # global cs_text_length

    # global SegmentIndex

    # global exception_text

    global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount
    # global min_bytes_index
    # global min_byte

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount
    # global max_bytes_index
    # global max_byte

    # global sequence_bytes
    global sequence_bytes_address
    # global sequence_bytes_original_amount
    # global sequence_bytes_amount
    # global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    # global suggested_sequence_bytes_offset
    # global suggested_sequence_bytes_offset_matches
    # global suggested_sequence_bytes_offset_mismatches

    # global suggested_hardcore_sequence_bytes_offset
    # global suggested_hardcore_sequence_bytes_offset_matches
    # global suggested_hardcore_sequence_bytes_offset_mismatches

    # global original_bytes
    global original_bytes_address
    global original_bytes_size
    global original_bytes_amount
    # global original_bytes_index
    # global original_byte

    global fixed_bytes
    global fixed_bytes_address
    global fixed_bytes_size
    global fixed_bytes_amount
    global fixed_bytes_index
    global fixed_byte

    # Function Variables

    offset = None

    bytes_power = None

    # Start

    fixed_bytes = []
    fixed_bytes_address = original_bytes_address
    fixed_bytes_size = original_bytes_size - mem_hole_size
    fixed_bytes_amount = original_bytes_amount
    fixed_bytes_index = None
    fixed_byte = None

    offset = fixed_bytes_address - sequence_bytes_address

    # print(CheckHexText(fixed_bytes_address, AddressesLength, True))
    # print(CheckHexText(fixed_bytes_size, SizesLength, True))

    for fixed_bytes_index in range(0, fixed_bytes_amount):
        bytes_power = int(math.pow(0x00000100, fixed_bytes_index))

        fixed_byte = int((fixed_bytes_size & (0x000000FF * bytes_power)) / bytes_power)

        fixed_bytes.append(fixed_byte)

        PatchSequenceByte(offset + fixed_bytes_index, fixed_byte)  # no need to check if the result is True because if it doesn't so it's just not patching it

        # print(CheckHexText(fixed_byte, BytesLength, True))


def CheckSequenceBytesText():
    result = None

    # Global Variables

    # global dry_run
    # global verbose

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_FileSize
    # global SegmentAfterMemHole_MemorySize

    global BytesLength
    global SizesLength
    global AddressesLength

    # global sequence_bytes_offset_use_options

    # global successes
    # global failures

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches
    # global segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches

    # global head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global static_TP_text
    # global static_TP_text_length

    # global cs_text
    # global cs_text_length

    # global SegmentIndex

    # global exception_text

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount
    # global min_bytes_index
    # global min_byte

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount
    # global max_bytes_index
    # global max_byte

    # global sequence_bytes
    # global sequence_bytes_address
    # global sequence_bytes_original_amount
    global sequence_bytes_amount
    # global sequence_bytes_offset
    global sequence_bytes_index
    global sequence_byte

    # global suggested_sequence_bytes_offset
    # global suggested_sequence_bytes_offset_matches
    # global suggested_sequence_bytes_offset_mismatches

    # global suggested_hardcore_sequence_bytes_offset
    # global suggested_hardcore_sequence_bytes_offset_matches
    # global suggested_hardcore_sequence_bytes_offset_mismatches

    # global original_bytes
    # global original_bytes_address
    # global original_bytes_size
    # global original_bytes_amount
    # global original_bytes_index
    # global original_byte

    # global fixed_bytes
    # global fixed_bytes_address
    # global fixed_bytes_size
    # global fixed_bytes_amount
    # global fixed_bytes_index
    # global fixed_byte

    # Function Variables

    current_result = None

    # Start

    if sequence_bytes_amount > 0:
        sequence_bytes_index = sequence_bytes_amount - 1

        while sequence_bytes_index >= 0:
            sequence_byte = CheckSequenceByte(sequence_bytes_index)

            if sequence_byte is not None:
                if current_result is None:
                    current_result = ""

                current_result += CheckHexText(sequence_byte, BytesLength, (current_result == ""))
            else:
                break

            sequence_bytes_index -= 1

    result = current_result

    return result


def TestSequenceBytesOffset(offset, min_size, max_size):  # set min or max as 0 or below in order to ignore them
    result = None

    # Global Variables

    # global dry_run
    # global verbose

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_FileSize
    # global SegmentAfterMemHole_MemorySize

    global BytesLength
    global SizesLength
    global AddressesLength

    # global sequence_bytes_offset_use_options

    # global successes
    # global failures

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches
    # global segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches

    # global head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global static_TP_text
    # global static_TP_text_length

    # global cs_text
    # global cs_text_length

    # global SegmentIndex

    # global exception_text

    # global mem_hole_size

    global min_bytes_size
    global min_bytes_amount
    global min_bytes_estimated_amount
    # global min_bytes_index
    # global min_byte

    global max_bytes_size
    global max_bytes_amount
    global max_bytes_estimated_amount
    # global max_bytes_index
    # global max_byte

    # global sequence_bytes
    # global sequence_bytes_address
    # global sequence_bytes_original_amount
    global sequence_bytes_amount
    # global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    # global suggested_sequence_bytes_offset
    # global suggested_sequence_bytes_offset_matches
    # global suggested_sequence_bytes_offset_mismatches

    # global suggested_hardcore_sequence_bytes_offset
    # global suggested_hardcore_sequence_bytes_offset_matches
    # global suggested_hardcore_sequence_bytes_offset_mismatches

    # global original_bytes
    # global original_bytes_address
    # global original_bytes_size
    # global original_bytes_amount
    # global original_bytes_index
    # global original_byte

    # global fixed_bytes
    # global fixed_bytes_address
    # global fixed_bytes_size
    # global fixed_bytes_amount
    # global fixed_bytes_index
    # global fixed_byte

    # Function Variables

    current_min_bytes_size = None
    current_min_bytes_amount = None
    current_min_bytes_estimated_amount = None

    current_max_bytes_size = None
    current_max_bytes_amount = None
    current_max_bytes_estimated_amount = None

    current_bytes_amount = None
    current_bytes_estimated_amount = None
    current_bytes_index = None
    current_byte = None

    method_found = False
    error_found = False

    # Start

    if sequence_bytes_amount > offset:
        if min_size <= 0:
            current_min_bytes_size = min_bytes_size
        else:
            if min_size <= min_bytes_size:
                current_min_bytes_size = min_bytes_size
            else:
                if min_size >= max_bytes_size:
                    current_min_bytes_size = max_bytes_size
                else:
                    current_min_bytes_size = min_size

        if current_min_bytes_size == min_bytes_size:
            current_min_bytes_amount = min_bytes_amount
            current_min_bytes_estimated_amount = min_bytes_estimated_amount
        elif current_min_bytes_size == max_bytes_size:
            current_min_bytes_amount = max_bytes_amount
            current_min_bytes_estimated_amount = max_bytes_estimated_amount
        else:
            current_min_bytes_amount = int(math.ceil(math.log(current_min_bytes_size, 0x100)))

            if current_min_bytes_amount == min_bytes_amount:
                current_min_bytes_estimated_amount = min_bytes_estimated_amount
            elif current_min_bytes_amount == max_bytes_amount:
                current_min_bytes_estimated_amount = max_bytes_estimated_amount
            else:
                current_min_bytes_estimated_amount = int(math.pow(2, int(math.ceil(math.log(current_min_bytes_amount, 2)))))

        if max_size <= 0:
            current_max_bytes_size = max_bytes_size
        else:
            if max_size >= max_bytes_size:
                current_max_bytes_size = max_bytes_size
            else:
                if max_size <= min_bytes_size:
                    current_max_bytes_size = min_bytes_size
                else:
                    current_max_bytes_size = max_size

        if current_max_bytes_size == max_bytes_size:
            current_max_bytes_amount = max_bytes_amount
            current_max_bytes_estimated_amount = max_bytes_estimated_amount
        elif current_max_bytes_size == min_bytes_size:
            current_max_bytes_amount = min_bytes_amount
            current_max_bytes_estimated_amount = min_bytes_estimated_amount
        else:
            current_max_bytes_amount = int(math.ceil(math.log(current_max_bytes_size, 0x100)))

            if current_max_bytes_amount == min_bytes_amount:
                current_max_bytes_estimated_amount = min_bytes_estimated_amount
            elif current_max_bytes_amount == max_bytes_amount:
                current_max_bytes_estimated_amount = max_bytes_estimated_amount
            else:
                current_max_bytes_estimated_amount = int(math.pow(2, int(math.ceil(math.log(current_max_bytes_amount, 2)))))

        current_bytes_amount = current_min_bytes_amount

        while current_bytes_amount <= current_max_bytes_amount:
            if current_bytes_amount == current_min_bytes_amount:
                current_bytes_estimated_amount = current_min_bytes_estimated_amount
            elif current_bytes_amount == current_max_bytes_amount:
                current_bytes_estimated_amount = current_max_bytes_estimated_amount
            else:
                current_bytes_estimated_amount = int(math.pow(2, int(math.ceil(math.log(current_bytes_amount, 2)))))

            for current_bytes_index in range(current_bytes_amount, current_bytes_estimated_amount):
                current_byte = CheckSequenceByte(sequence_bytes_amount - offset - current_bytes_estimated_amount + current_bytes_index)

                if current_byte is None or current_byte != 0:
                    error_found = True

                    break

            if error_found is True:
                error_found = False
            else:
                if (
                    CheckSequenceBytes(
                        sequence_bytes_amount - offset - current_bytes_estimated_amount
                        , current_bytes_estimated_amount
                        , current_min_bytes_size
                        , current_max_bytes_size
                    ) is True
                ):
                    method_found = True

            if method_found is True:
                break
            else:
                current_bytes_amount += 1

    result = method_found

    return result


def CheckSequenceBytesOffset(structures):  # returns True if found a suitable sequence bytes offset, False if didn't
    # the structures is an array of arrays, each structure is an array, set cells as None in order to skip them
    # structure cells:
    # 0 - cmd fixed splitted index offset
    # 1 - cmd fixed splitted min amount
    # 2 - cmd fixed splitted max amount
    # 3 - command
    # 4 - typeA
    # 5 - typeB
    # 6 - typeC
    # 7 - typeD
    # 8 - typeE
    # 9 - sequence bytes offset

    result = None

    # Global Variables

    # global dry_run
    # global verbose

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_FileSize
    # global SegmentAfterMemHole_MemorySize

    global BytesLength
    global SizesLength
    global AddressesLength

    global sequence_bytes_offset_use_options

    # global successes
    # global failures

    # global patched_bytes

    global first_segment_to_segment_before_memhole_matches
    # global segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches

    # global head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    global cmd_fixed_splitted
    global cmd_fixed_splitted_amount
    global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global static_TP_text
    # global static_TP_text_length

    # global cs_text
    # global cs_text_length

    # global SegmentIndex

    # global exception_text

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount
    # global min_bytes_index
    # global min_byte

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount
    # global max_bytes_index
    # global max_byte

    # global sequence_bytes
    # global sequence_bytes_address
    # global sequence_bytes_original_amount
    # global sequence_bytes_amount
    global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    global suggested_sequence_bytes_offset
    global suggested_sequence_bytes_offset_matches
    global suggested_sequence_bytes_offset_mismatches

    global suggested_hardcore_sequence_bytes_offset
    global suggested_hardcore_sequence_bytes_offset_matches
    global suggested_hardcore_sequence_bytes_offset_mismatches

    # global original_bytes
    # global original_bytes_address
    # global original_bytes_size
    # global original_bytes_amount
    # global original_bytes_index
    # global original_byte

    # global fixed_bytes
    # global fixed_bytes_address
    # global fixed_bytes_size
    # global fixed_bytes_amount
    # global fixed_bytes_index
    # global fixed_byte

    # Function Variables

    power_result = None
    power_result_start = None
    power_result_end = None

    last_cell = (cmd_fixed_splitted_index + 1 == cmd_fixed_splitted_amount)

    structure = None
    structure_cmd_fixed_splitted_index_offset = None
    structure_cmd_fixed_splitted_min_amount = None
    structure_cmd_fixed_splitted_max_amount = None
    structure_command = None
    structure_typeA = None
    structure_typeB = None
    structure_typeC = None
    structure_typeD = None
    structure_typeE = None
    structure_sequence_bytes_offset = None

    command = None
    typeA = None
    typeB = None
    typeC = None
    typeD = None
    typeE = None

    suggested_sequence_bytes_offset_level = 0

    suggested_hardcore_sequence_bytes_offset_level = 0

    overwrite_sequence_bytes_offset = (sequence_bytes_offset is None or ((sequence_bytes_offset_use_options & int("0001", 2)) > 0))

    method_found = False

    # Start

    sequence_bytes_offset = None

    suggested_sequence_bytes_offset = None

    suggested_hardcore_sequence_bytes_offset = None

    if cmd_fixed_splitted_index > 0:
        command = cmd_fixed_splitted[0]

        if cmd_fixed_splitted_index > 1:
            typeA = cmd_fixed_splitted[1]

            if cmd_fixed_splitted_index > 2:
                typeB = cmd_fixed_splitted[2]

                if cmd_fixed_splitted_index > 3:
                    typeC = cmd_fixed_splitted[3]

                    if cmd_fixed_splitted_index > 4:
                        typeD = cmd_fixed_splitted[4]

                        if cmd_fixed_splitted_index > 5:
                            typeE = cmd_fixed_splitted[5]

    for structure in structures:
        structure_cmd_fixed_splitted_index_offset = structure[0]
        structure_cmd_fixed_splitted_min_amount = structure[1]
        structure_cmd_fixed_splitted_max_amount = structure[2]
        structure_command = structure[3]
        structure_typeA = structure[4]
        structure_typeB = structure[5]
        structure_typeC = structure[6]
        structure_typeD = structure[7]
        structure_typeE = structure[8]
        structure_sequence_bytes_offset = structure[9]

        if structure_cmd_fixed_splitted_index_offset is None or cmd_fixed_splitted_index + structure_cmd_fixed_splitted_index_offset == cmd_fixed_splitted_amount:
            if structure_command is None or command is None or command == structure_command:
                if structure_cmd_fixed_splitted_min_amount is None or cmd_fixed_splitted_amount >= structure_cmd_fixed_splitted_min_amount:
                    if structure_cmd_fixed_splitted_max_amount is None or cmd_fixed_splitted_amount <= structure_cmd_fixed_splitted_max_amount:
                        if structure_typeA is None or typeA is None or typeA == structure_typeA:
                            if structure_typeB is None or typeB is None or typeB == structure_typeB:
                                if structure_typeC is None or typeC is None or typeC == structure_typeC:
                                    if structure_typeD is None or typeD is None or typeD == structure_typeD:
                                        if structure_typeE is None or typeE is None or typeE == structure_typeE:
                                            sequence_bytes_offset = structure_sequence_bytes_offset

                                            if suggested_sequence_bytes_offset_level < 8:
                                                suggested_sequence_bytes_offset = structure_sequence_bytes_offset

                                                suggested_sequence_bytes_offset_level = 8

                                            if suggested_hardcore_sequence_bytes_offset_level < 8:
                                                suggested_hardcore_sequence_bytes_offset = structure_sequence_bytes_offset

                                                suggested_hardcore_sequence_bytes_offset_level = 8

                                            break
                                        else:
                                            if suggested_sequence_bytes_offset_level < 7:
                                                suggested_sequence_bytes_offset = structure_sequence_bytes_offset

                                                suggested_sequence_bytes_offset_level = 7

                                            if suggested_hardcore_sequence_bytes_offset_level < 7:
                                                suggested_hardcore_sequence_bytes_offset = structure_sequence_bytes_offset

                                                suggested_hardcore_sequence_bytes_offset_level = 7
                                    else:
                                        if suggested_sequence_bytes_offset_level < 6:
                                            suggested_sequence_bytes_offset = structure_sequence_bytes_offset

                                            suggested_sequence_bytes_offset_level = 6

                                        if suggested_hardcore_sequence_bytes_offset_level < 6:
                                            suggested_hardcore_sequence_bytes_offset = structure_sequence_bytes_offset

                                            suggested_hardcore_sequence_bytes_offset_level = 6
                                else:
                                    if suggested_sequence_bytes_offset_level < 5:
                                        suggested_sequence_bytes_offset = structure_sequence_bytes_offset

                                        suggested_sequence_bytes_offset_level = 5

                                    if suggested_hardcore_sequence_bytes_offset_level < 5:
                                        suggested_hardcore_sequence_bytes_offset = structure_sequence_bytes_offset

                                        suggested_hardcore_sequence_bytes_offset_level = 5
                            else:
                                if suggested_sequence_bytes_offset_level < 4:
                                    suggested_sequence_bytes_offset = structure_sequence_bytes_offset

                                    suggested_sequence_bytes_offset_level = 4

                                if suggested_hardcore_sequence_bytes_offset_level < 4:
                                    suggested_hardcore_sequence_bytes_offset = structure_sequence_bytes_offset

                                    suggested_hardcore_sequence_bytes_offset_level = 4
                        else:
                            if suggested_hardcore_sequence_bytes_offset_level < 3:
                                suggested_hardcore_sequence_bytes_offset = structure_sequence_bytes_offset

                                suggested_hardcore_sequence_bytes_offset_level = 3
                    else:
                        if suggested_hardcore_sequence_bytes_offset_level < 2:
                            suggested_hardcore_sequence_bytes_offset = structure_sequence_bytes_offset

                            suggested_hardcore_sequence_bytes_offset_level = 2
                else:
                    if suggested_hardcore_sequence_bytes_offset_level < 1:
                        suggested_hardcore_sequence_bytes_offset = structure_sequence_bytes_offset

                        suggested_hardcore_sequence_bytes_offset_level = 1

    if sequence_bytes_offset is not None:
        if TestSequenceBytesOffset(sequence_bytes_offset, -1, -1) is False:
            sequence_bytes_offset = None

    if suggested_sequence_bytes_offset is not None:
        if TestSequenceBytesOffset(suggested_sequence_bytes_offset, -1, -1) is False:
            suggested_sequence_bytes_offset = None

    if suggested_hardcore_sequence_bytes_offset is not None:
        if TestSequenceBytesOffset(suggested_hardcore_sequence_bytes_offset, -1, -1) is False:
            suggested_hardcore_sequence_bytes_offset = None

    if suggested_hardcore_sequence_bytes_offset is None:
        if last_cell is True:
            power_result_start = math.pow(2, -1)
            power_result_end = math.pow(2, 3)
        else:
            power_result_start = math.pow(2, 3)
            power_result_end = math.pow(2, -1)

        if last_cell is True:
            power_result = power_result_start / 2
        else:
            power_result = power_result_start * 2

        suggested_hardcore_sequence_bytes_offset = -1

        while suggested_hardcore_sequence_bytes_offset != int(power_result_end):
            if last_cell is True:
                power_result *= 2
            else:
                power_result /= 2

            suggested_hardcore_sequence_bytes_offset = int(power_result)

            if (
                suggested_hardcore_sequence_bytes_offset != 8
                # and suggested_hardcore_sequence_bytes_offset != 2 -> seen it already
            ):  # haven't seen these in use
                if TestSequenceBytesOffset(suggested_hardcore_sequence_bytes_offset, -1, -1) is True:
                    method_found = True

                    break

        if method_found is True:
            method_found = False
        else:
            suggested_hardcore_sequence_bytes_offset = None

    if sequence_bytes_offset is not None:
        first_segment_to_segment_before_memhole_matches += 1

    if suggested_sequence_bytes_offset is not None:
        if suggested_sequence_bytes_offset == sequence_bytes_offset:
            suggested_sequence_bytes_offset_matches += 1
        else:
            suggested_sequence_bytes_offset_mismatches += 1

    if suggested_hardcore_sequence_bytes_offset is not None:
        if suggested_hardcore_sequence_bytes_offset == sequence_bytes_offset:
            suggested_hardcore_sequence_bytes_offset_matches += 1
        else:
            suggested_hardcore_sequence_bytes_offset_mismatches += 1

    if overwrite_sequence_bytes_offset is True:
        overwrite_using_suggested_sequence_bytes_offset = (
            suggested_sequence_bytes_offset is not None and ((sequence_bytes_offset_use_options & int("0010", 2)) > 0)
        )

        overwrite_using_suggested_hardcore_sequence_bytes_offset = (
            suggested_hardcore_sequence_bytes_offset is not None and ((sequence_bytes_offset_use_options & int("0100", 2)) > 0)
        )

        if (
            overwrite_using_suggested_sequence_bytes_offset is True
            or overwrite_using_suggested_hardcore_sequence_bytes_offset is True
        ):
            prioritize_suggested_hardcore_sequence_bytes_offset_over_suggested_sequence_bytes_offset = ((sequence_bytes_offset_use_options & int("1000", 2)) > 0)

            if prioritize_suggested_hardcore_sequence_bytes_offset_over_suggested_sequence_bytes_offset is True:
                if overwrite_using_suggested_hardcore_sequence_bytes_offset is True:
                    sequence_bytes_offset = suggested_hardcore_sequence_bytes_offset
                elif overwrite_using_suggested_sequence_bytes_offset is True:
                    sequence_bytes_offset = suggested_sequence_bytes_offset
            else:
                if overwrite_using_suggested_sequence_bytes_offset is True:
                    sequence_bytes_offset = suggested_sequence_bytes_offset
                elif overwrite_using_suggested_hardcore_sequence_bytes_offset is True:
                    sequence_bytes_offset = suggested_hardcore_sequence_bytes_offset

    result = (sequence_bytes_offset is not None)

    return result


def check_static_TP():  # returns -1 in case of failure, 0 in case of not finding a match, and 1 in case of success
    result = None

    # Global Variables

    # global dry_run
    global verbose

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_FileSize
    # global SegmentAfterMemHole_MemorySize

    global BytesLength
    global SizesLength
    global AddressesLength

    # global sequence_bytes_offset_use_options

    global successes
    # global failures

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches
    # global segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches

    global head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    global cmd_fixed_splitted
    global cmd_fixed_splitted_amount
    global cmd_fixed_splitted_index
    global cmd_fixed_splitted_cell
    global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    global static_TP_text
    global static_TP_text_length

    # global cs_text
    # global cs_text_length

    # global SegmentIndex

    global exception_text

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    global min_bytes_estimated_amount
    # global min_bytes_index
    # global min_byte

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount
    # global max_bytes_index
    # global max_byte

    # global sequence_bytes
    # global sequence_bytes_address
    # global sequence_bytes_original_amount
    global sequence_bytes_amount
    global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    global suggested_sequence_bytes_offset
    # global suggested_sequence_bytes_offset_matches
    # global suggested_sequence_bytes_offset_mismatches

    global suggested_hardcore_sequence_bytes_offset
    # global suggested_hardcore_sequence_bytes_offset_matches
    # global suggested_hardcore_sequence_bytes_offset_mismatches

    # global original_bytes
    # global original_bytes_address
    global original_bytes_size
    global original_bytes_amount
    # global original_bytes_index
    # global original_byte

    # global fixed_bytes
    global fixed_bytes_address
    global fixed_bytes_size
    global fixed_bytes_amount
    # global fixed_bytes_index
    # global fixed_byte

    # Function Variables

    SequenceBytesText = None

    method_found = False
    error_found = False

    # Start

    if cmd_fixed_splitted_cell_length >= static_TP_text_length:
        if cmd_fixed_splitted_cell[:static_TP_text_length] == static_TP_text:
            if cmd_fixed_splitted_cell_length > static_TP_text_length:
                exception_text = "can't parse static_TP (can't handle additions/substractions or any math functions)"

                error_found = True
            else:
                CreateSequence(head, None)  # no need to check for the result, assuming it is True

                if sequence_bytes_amount < min_bytes_estimated_amount:
                    exception_text = (
                        "the sequence bytes amount"
                        + ' ' + str(sequence_bytes_amount)
                        + ' ' + "is smaller than the min bytes estimated amount"
                        + ' ' + str(min_bytes_estimated_amount)
                    )

                    error_found = True
                else:
                    if (
                        CheckSequenceBytesOffset(
                            [
                                [1, 3, 3, "lea", None, None, None, None, None, 0]
                            ]
                        ) is False
                    ):
                        exception_text = "couldn't find a suitable sequence bytes offset"

                        if (
                            cmd_fixed_splitted_index + 1 != cmd_fixed_splitted_amount
                        ):
                            exception_text += ',' + ' ' + "not supporting a command that static_TP isn't in the last cell"

                        if sequence_bytes_offset is not None:
                            exception_text += '\t' + "offset:" + ' ' + str(sequence_bytes_offset)

                        if suggested_sequence_bytes_offset is not None:
                            exception_text += '\t' + "suggested offset:" + ' ' + str(suggested_sequence_bytes_offset)

                        if suggested_hardcore_sequence_bytes_offset is not None:
                            exception_text += '\t' + "suggested hardcore offset:" + ' ' + str(suggested_hardcore_sequence_bytes_offset)

                        error_found = True
                    else:
                        if verbose is True:
                            SequenceBytesText = CheckSequenceBytesText()

                        PatchSequenceBytes()

                        if verbose is True:
                            print(
                                "Patched static_TP bytes"
                                + '\t' + "command:" + ' ' + '\t'.join(cmd_fixed_splitted)
                                + '\t' + "address:" + ' ' + CheckHexText(fixed_bytes_address, AddressesLength, True)
                                + '\t' + "position:" + ' ' + str(cmd_fixed_splitted_index + 1) + ' ' + "out of:" + ' ' + str(cmd_fixed_splitted_amount)
                                + '\t' + "offset:" + ' ' + str(sequence_bytes_offset)
                                + (('\t' + "sequence bytes:" + ' ' + SequenceBytesText) if SequenceBytesText is not None else "")
                                + '\t' + "original bytes:" + ' ' + CheckHexText(original_bytes_size, original_bytes_amount * 2, True)
                                + '\t' + "patched bytes:" + ' ' + CheckHexText(fixed_bytes_size, fixed_bytes_amount * 2, True)
                            )

                        successes += 1

                        method_found = True

    if method_found is True:
        result = 1
    elif error_found is True:
        result = -1
    else:
        result = 0

    return result


def check_cs():  # returns -1 in case of failure, 0 in case of not finding a match, and 1 in case of success
    result = None

    # Global Variables

    # global dry_run
    global verbose

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_FileSize
    global SegmentAfterMemHole_MemorySize

    global BytesLength
    global SizesLength
    global AddressesLength

    # global sequence_bytes_offset_use_options

    global successes
    # global failures

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches
    # global segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches

    global head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    global cmd_fixed_splitted
    global cmd_fixed_splitted_amount
    global cmd_fixed_splitted_index
    global cmd_fixed_splitted_cell
    global cmd_fixed_splitted_cell_length
    global cmd_fixed_splitted_cell_index

    # global static_TP_text
    # global static_TP_text_length

    global cs_text
    global cs_text_length

    # global SegmentIndex

    global exception_text

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    global min_bytes_estimated_amount
    # global min_bytes_index
    # global min_byte

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount
    # global max_bytes_index
    # global max_byte

    # global sequence_bytes
    # global sequence_bytes_address
    # global sequence_bytes_original_amount
    global sequence_bytes_amount
    global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    global suggested_sequence_bytes_offset
    # global suggested_sequence_bytes_offset_matches
    # global suggested_sequence_bytes_offset_mismatches

    global suggested_hardcore_sequence_bytes_offset
    # global suggested_hardcore_sequence_bytes_offset_matches
    # global suggested_hardcore_sequence_bytes_offset_mismatches

    # global original_bytes
    # global original_bytes_address
    global original_bytes_size
    global original_bytes_amount
    # global original_bytes_index
    # global original_byte

    # global fixed_bytes
    global fixed_bytes_address
    global fixed_bytes_size
    global fixed_bytes_amount
    # global fixed_bytes_index
    # global fixed_byte

    # Function Variables

    cs_address = None

    SequenceBytesText = None

    method_found = False
    error_found = False

    # Start

    if cmd_fixed_splitted_cell_length >= cs_text_length + 2:  # need at least 1 number and 1 'h' (mentioning an hexa number)
        if cmd_fixed_splitted_cell[:cs_text_length] == cs_text:
            for cmd_fixed_splitted_cell_index in range(cs_text_length, cmd_fixed_splitted_cell_length):
                if cmd_fixed_splitted_cell[cmd_fixed_splitted_cell_index] in string.hexdigits:
                    continue
                elif cmd_fixed_splitted_cell[cmd_fixed_splitted_cell_index] == 'h':
                    if cmd_fixed_splitted_cell_index > cs_text_length:
                        if cmd_fixed_splitted_cell_index < cmd_fixed_splitted_cell_length - 1:
                            exception_text = "can't parse cs (can't handle additions/substractions or any math functions)"

                            error_found = True
                        else:
                            method_found = True

                    break
                else:
                    break

            if method_found is True:
                method_found = False

                CreateSequence(head, None)  # no need to check for the result, assuming it is True

                if sequence_bytes_amount < min_bytes_estimated_amount:
                    exception_text = (
                        "the sequence bytes amount"
                        + ' ' + str(sequence_bytes_amount)
                        + ' ' + "is smaller than the min bytes estimated amount"
                        + ' ' + str(min_bytes_estimated_amount)
                    )

                    error_found = True
                else:
                    cs_address = int(cmd_fixed_splitted_cell[cs_text_length:cmd_fixed_splitted_cell_length - 1], 16)

                    if (
                        cs_address >= SegmentAfterMemHole_Unmapped_VirtualAddress
                        and cs_address <= SegmentAfterMemHole_Unmapped_VirtualAddress + SegmentAfterMemHole_MemorySize - 1
                    ):
                        if (
                            CheckSequenceBytesOffset(
                                [
                                    [1, 3, 3, "add", None, None, None, None, None, 0]
                                    , [1, 3, 3, "and", None, None, None, None, None, 0]
                                    , [1, None, None, "call", "qword", "ptr", None, None, None, 0]
                                    , [1, 3, 3, "cmp", None, None, None, None, None, 0]
                                    , [1, None, None, "dec", "qword", "ptr", None, None, None, 0]
                                    , [1, None, None, "dec", "dword", "ptr", None, None, None, 0]
                                    , [1, None, None, "div", "dword", "ptr", None, None, None, 0]
                                    , [1, None, None, "inc", "qword", "ptr", None, None, None, 0]
                                    , [1, None, None, "inc", "dword", "ptr", None, None, None, 0]
                                    , [1, None, None, "jmp", "qword", "ptr", None, None, None, 0]
                                    , [1, 3, 3, "lea", None, None, None, None, None, 0]
                                    , [1, None, None, "lock", "dec", "dword", "ptr", None, None, 0]
                                    , [1, 3, 3, "mov", None, None, None, None, None, 0]
                                    , [1, 3, 3, "movbe", None, None, None, None, None, 0]
                                    , [1, None, None, "movsx", None, "byte", "ptr", None, None, 0]
                                    , [1, None, None, "movsxd", None, "dword", "ptr", None, None, 0]
                                    , [1, None, None, "movzx", None, "byte", "ptr", None, None, 0]
                                    , [1, None, None, "movzx", None, "word", "ptr", None, None, 0]
                                    , [1, 3, 3, "or", None, None, None, None, None, 0]
                                    , [1, None, None, "setz", "byte", "ptr", None, None, None, 0]
                                    , [1, 3, 3, "sub", None, None, None, None, None, 0]
                                    , [1, None, None, "vaddps", None, None, "xmmword", "ptr", None, 0]
                                    , [1, None, None, "vaddsd", None, None, "qword", "ptr", None, 0]
                                    , [1, None, None, "vandps", None, None, "xmmword", "ptr", None, 0]
                                    , [1, None, None, "vbroadcastsd", None, "qword", "ptr", None, None, 0]
                                    , [1, None, None, "vbroadcastss", None, "dword", "ptr", None, None, 0]
                                    , [1, None, None, "vcmpltps", None, None, "xmmword", "ptr", None, 1]
                                    , [1, None, None, "vcvtsi2sd", None, None, "qword", "ptr", None, 0]
                                    , [1, None, None, "vcvtsi2ss", None, None, "dword", "ptr", None, 0]
                                    , [1, None, None, "vdivss", None, None, "dword", "ptr", None, 0]
                                    , [1, None, None, "vmaxps", None, None, "xmmword", "ptr", None, 0]
                                    , [1, None, None, "vmaxss", None, None, "dword", "ptr", None, 0]
                                    , [1, None, None, "vminps", None, None, "xmmword", "ptr", None, 0]
                                    , [1, None, None, "vmovdqu", None, "xmmword", "ptr", None, None, 0]
                                    , [1, None, None, "vmovdqu", None, "ymmword", "ptr", None, None, 0]
                                    , [1, None, None, "vmovhpd", None, None, "qword", "ptr", None, 0]
                                    , [1, None, None, "vmovq", None, "qword", "ptr", None, None, 0]
                                    , [1, None, None, "vmovsd", None, "qword", "ptr", None, None, 0]
                                    , [1, None, None, "vmovss", None, "dword", "ptr", None, None, 0]
                                    , [1, None, None, "vmovupd", None, "xmmword", "ptr", None, None, 0]
                                    , [1, None, None, "vmovups", None, "xmmword", "ptr", None, None, 0]
                                    , [1, None, None, "vmovups", None, "ymmword", "ptr", None, None, 0]
                                    , [1, None, None, "vmulps", None, None, "xmmword", "ptr", None, 0]
                                    , [1, None, None, "vmulss", None, None, "dword", "ptr", None, 0]
                                    , [1, None, None, "vpand", None, None, "xmmword", "ptr", None, 0]
                                    , [1, None, None, "vsubss", None, None, "dword", "ptr", None, 0]
                                    , [1, None, None, "vucomiss", None, "dword", "ptr", None, None, 0]
                                    , [1, 3, 3, "xchg", None, None, None, None, None, 0]
                                    , [1, 3, 3, "xor", None, None, None, None, None, 0]
                                    , [2, 3, 3, "add", None, None, None, None, None, 0]
                                    , [2, None, None, "add", "dword", "ptr", None, None, None, 1]
                                    , [2, None, None, "and", "qword", "ptr", None, None, None, 1]
                                    , [2, None, None, "and", "dword", "ptr", None, None, None, 4]
                                    , [2, 4, 4, "bextr", None, None, None, None, None, 0]
                                    , [2, 3, 3, "cmp", None, None, None, None, None, 0]
                                    , [2, None, None, "cmp", "qword", "ptr", None, None, None, 1]
                                    , [2, None, None, "cmp", "dword", "ptr", None, None, None, 1]
                                    , [2, None, None, "cmp", "byte", "ptr", None, None, None, 1]
                                    , [2, None, None, "lock", "cmpxchg", None, None, None, None, 0]
                                    , [2, None, None, "lock", "xadd", None, None, None, None, 0]
                                    , [2, 3, 3, "mov", None, None, None, None, None, 0]
                                    , [2, None, None, "mov", "qword", "ptr", None, None, None, 4]
                                    , [2, None, None, "mov", "dword", "ptr", None, None, None, 4]
                                    , [2, None, None, "mov", "word", "ptr", None, None, None, 2]
                                    , [2, None, None, "mov", "byte", "ptr", None, None, None, 1]
                                    , [2, None, None, "or", "byte", "ptr", None, None, None, 1]
                                    , [2, 3, 3, "sub", None, None, None, None, None, 0]
                                    , [2, None, None, "test", "byte", "ptr", None, None, None, 1]
                                    , [2, None, None, "vinsertps", None, None, "dword", "ptr", None, 1]
                                    , [2, None, None, "vmovdqu", "xmmword", "ptr", None, None, None, 0]
                                    , [2, None, None, "vmovlps", "qword", "ptr", None, None, None, 0]
                                    , [2, None, None, "vmovsd", "qword", "ptr", None, None, None, 0]
                                    , [2, None, None, "vmovss", "dword", "ptr", None, None, None, 0]
                                    , [2, None, None, "vmovupd", "xmmword", "ptr", None, None, None, 0]
                                    , [2, None, None, "vmovups", "xmmword", "ptr", None, None, None, 0]
                                    , [2, None, None, "vmovups", "ymmword", "ptr", None, None, None, 0]
                                    , [3, None, None, "mov", "dword", "ptr", None, None, None, 4]
                                ]
                            ) is False
                        ):
                            exception_text = "couldn't find a suitable sequence bytes offset"

                            if (
                                cmd_fixed_splitted_index + 1 != cmd_fixed_splitted_amount
                                and cmd_fixed_splitted_index + 2 != cmd_fixed_splitted_amount
                                and cmd_fixed_splitted_index + 3 != cmd_fixed_splitted_amount
                            ):
                                exception_text += ',' + ' ' + "not supporting a command that cs isn't in a range between last cell to 2 cells before it"

                            if sequence_bytes_offset is not None:
                                exception_text += '\t' + "offset:" + ' ' + str(sequence_bytes_offset)

                            if suggested_sequence_bytes_offset is not None:
                                exception_text += '\t' + "suggested offset:" + ' ' + str(suggested_sequence_bytes_offset)

                            if suggested_hardcore_sequence_bytes_offset is not None:
                                exception_text += '\t' + "suggested hardcore offset:" + ' ' + str(suggested_hardcore_sequence_bytes_offset)

                            error_found = True
                        else:
                            if verbose is True:
                                SequenceBytesText = CheckSequenceBytesText()

                            PatchSequenceBytes()

                            if verbose is True:
                                print(
                                    "Patched cs bytes"
                                    + '\t' + "command:" + ' ' + '\t'.join(cmd_fixed_splitted)
                                    + '\t' + "address:" + ' ' + CheckHexText(fixed_bytes_address, AddressesLength, True)
                                    + '\t' + "position:" + ' ' + str(cmd_fixed_splitted_index + 1) + ' ' + "out of:" + ' ' + str(cmd_fixed_splitted_amount)
                                    + '\t' + "offset:" + ' ' + str(sequence_bytes_offset)
                                    + (('\t' + "sequence bytes:" + ' ' + SequenceBytesText) if SequenceBytesText is not None else "")
                                    + '\t' + "original bytes:" + ' ' + CheckHexText(original_bytes_size, original_bytes_amount * 2, True)
                                    + '\t' + "patched bytes:" + ' ' + CheckHexText(fixed_bytes_size, fixed_bytes_amount * 2, True)
                                )

                            successes += 1

                            method_found = True

    if method_found is True:
        result = 1
    elif error_found is True:
        result = -1
    else:
        result = 0

    return result


def fix_addresses():
    # Global Variables

    # global dry_run
    global verbose

    global FirstSegment_VirtualAddress

    global SegmentBeforeMemHole_VirtualAddress

    global SegmentAfterMemHole_Unmapped_VirtualAddress
    global SegmentAfterMemHole_Mapped_VirtualAddress
    global SegmentAfterMemHole_FileSize
    global SegmentAfterMemHole_MemorySize

    global BytesLength
    global SizesLength
    global AddressesLength

    # global sequence_bytes_offset_use_options

    global successes
    global failures

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches
    global segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches

    global head

    global cmd
    global cmd_length
    global cmd_fixed
    global cmd_fixed_length
    global cmd_fixed_splitted
    global cmd_fixed_splitted_amount
    global cmd_fixed_splitted_index
    global cmd_fixed_splitted_cell
    global cmd_fixed_splitted_cell_length
    global cmd_fixed_splitted_cell_index

    # global static_TP_text
    # global static_TP_text_length

    # global cs_text
    # global cs_text_length

    global SegmentIndex

    global exception_text

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount
    # global min_bytes_index
    # global min_byte

    # global max_bytes_size
    # global max_bytes_amount
    global max_bytes_estimated_amount
    # global max_bytes_index
    # global max_byte

    # global sequence_bytes
    # global sequence_bytes_address
    # global sequence_bytes_original_amount
    global sequence_bytes_amount
    # global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    # global suggested_sequence_bytes_offset
    # global suggested_sequence_bytes_offset_matches
    # global suggested_sequence_bytes_offset_mismatches

    # global suggested_hardcore_sequence_bytes_offset
    # global suggested_hardcore_sequence_bytes_offset_matches
    # global suggested_hardcore_sequence_bytes_offset_mismatches

    # global original_bytes
    # global original_bytes_address
    global original_bytes_size
    global original_bytes_amount
    # global original_bytes_index
    # global original_byte

    # global fixed_bytes
    global fixed_bytes_address
    global fixed_bytes_size
    global fixed_bytes_amount
    # global fixed_bytes_index
    # global fixed_byte

    # Function Variables

    check_static_TP_result = None
    check_cs_result = None

    SequenceBytesText = None

    found_suitable_segment_index = False

    error_message = None

    method_found = False
    error_found = False

    # Start

    #
    # going through all of the functions/commands in all of the addresses from the first segment virtual address
    # to the segment after the mem hole mapped virtual address + its file size (not including the last one since it's an address of the next segment)
    #

    # going through all of the heads from first segment virtual address
    # to the segment before mem hole virtual address (not including the last one since it's an address of the next segment)

    print("")
    print("parsing addresses between the first segment to the segment before the memory hole")

    heads = CheckHeads(FirstSegment_VirtualAddress, SegmentBeforeMemHole_VirtualAddress - 1)

    for head in heads:
        # print(CheckHexText(head, AddressesLength, True))

        cmd = CheckCommand(head)

        if cmd is not None:
            cmd_length = len(cmd)

            if cmd_length > 0:
                # print(cmd)

                cmd_fixed = None
                cmd_fixed_length = None
                cmd_fixed_splitted = None
                cmd_fixed_splitted_amount = None
                cmd_fixed_splitted_index = None
                cmd_fixed_splitted_cell = None
                cmd_fixed_splitted_cell_length = None
                cmd_fixed_splitted_cell_index = None

                exception_text = None

                try:
                    cmd_fixed = cmd.split(';')[0].replace(',', ' ')

                    if cmd_fixed is not None:
                        cmd_fixed_length = len(cmd_fixed)

                        if cmd_fixed_length > 0:
                            cmd_fixed_splitted = filter(None, cmd_fixed.split(' '))

                            if cmd_fixed_splitted is not None:
                                cmd_fixed_splitted_amount = len(cmd_fixed_splitted)

                                if cmd_fixed_splitted_amount > 0:
                                    cmd_fixed_splitted_index = cmd_fixed_splitted_amount - 1

                                    while cmd_fixed_splitted_index >= 1:
                                        # 1 because the first 2 are always a command and either a type or a variable (register)
                                        # , and we don't need to check the command cell

                                        cmd_fixed_splitted_cell = cmd_fixed_splitted[cmd_fixed_splitted_index]
                                        cmd_fixed_splitted_cell_length = len(cmd_fixed_splitted_cell)

                                        if cmd_fixed_splitted_cell_length > 0:
                                            check_cs_result = check_cs()

                                            if check_cs_result == 1:
                                                method_found = True
                                            elif check_cs_result == -1:
                                                error_found = True
                                            else:
                                                check_static_TP_result = check_static_TP()

                                                if check_static_TP_result == 1:
                                                    method_found = True
                                                elif check_static_TP_result == -1:
                                                    error_found = True

                                            if method_found is True:
                                                method_found = False

                                                break
                                            elif error_found is True:
                                                error_found = False

                                                raise Exception(None)

                                        cmd_fixed_splitted_index -= 1
                except Exception:
                    error_message = []

                    error_message.append("can't parse.")

                    if exception_text is not None:
                        error_message.append("reason:" + ' ' + exception_text)

                    error_message.append("address:" + ' ' + CheckHexText(head, AddressesLength, True))

                    if cmd_fixed_splitted is not None:
                        error_message.append("command:" + ' ' + '\t'.join(cmd_fixed_splitted))

                    if cmd_fixed_splitted_index is not None:
                        error_message.append("position:" + ' ' + str(cmd_fixed_splitted_index + 1) + ' ' + "out of:" + ' ' + str(cmd_fixed_splitted_amount))

                    if CreateSequence(head, None) is True:
                        SequenceBytesText = CheckSequenceBytesText()

                        if SequenceBytesText is not None:
                            error_message.append("sequence bytes:" + ' ' + SequenceBytesText)

                    print('\t'.join(error_message))

                    failures += 1

    print("")
    print("finished parsing addresses between first segment to the segment before the memory hole")

    # going through all of the addresses from segment before mem hole virtual address
    # to the segment after the mem hole mapped virtual address + its file size (not including the last one since it's an address of the next segment)

    print("")
    print("parsing addresses between the segment before the memory hole to the segment after the memory hole and its file size")

    # print(CheckHexText(SegmentAfterMemHole_Mapped_VirtualAddress + SegmentAfterMemHole_FileSize, AddressesLength, True))
    # print(CheckHexText(SegmentAfterMemHole_Mapped_VirtualAddress + SegmentAfterMemHole_FileSize - 8 + 1, AddressesLength, True))

    SegmentIndex = SegmentBeforeMemHole_VirtualAddress

    while SegmentIndex < SegmentAfterMemHole_Mapped_VirtualAddress + SegmentAfterMemHole_FileSize - 8 + 1:
        if found_suitable_segment_index is False:
            if SegmentIndex % 8 == 0:
                found_suitable_segment_index = True

        if found_suitable_segment_index is False:
            SegmentIndex += 1
        else:
            CreateSequence(SegmentIndex, 8)  # no need to check for the result, assuming it is True

            if (
                TestSequenceBytesOffset(
                    sequence_bytes_amount - max_bytes_estimated_amount
                    , SegmentAfterMemHole_Unmapped_VirtualAddress
                    , SegmentAfterMemHole_Unmapped_VirtualAddress + SegmentAfterMemHole_MemorySize - 1
                ) is True
            ):
                if verbose is True:
                    SequenceBytesText = CheckSequenceBytesText()

                PatchSequenceBytes()

                if verbose is True:
                    print(
                        "Patched memory hole segments bytes"
                        + '\t' + "address:" + ' ' + CheckHexText(fixed_bytes_address, AddressesLength, True)
                        + '\t' + "offset:" + ' ' + str(8 - max_bytes_estimated_amount)
                        + (('\t' + "sequence bytes:" + ' ' + SequenceBytesText) if SequenceBytesText is not None else "")
                        + '\t' + "original bytes:" + ' ' + CheckHexText(original_bytes_size, original_bytes_amount * 2, True)
                        + '\t' + "patched bytes:" + ' ' + CheckHexText(fixed_bytes_size, fixed_bytes_amount * 2, True)
                    )

                successes += 1

                segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches += 1

            SegmentIndex += 8

        # print(str(SegmentIndex))

    print("")
    print("finished parsing addresses between the segment before the memory hole to the segment after the memory hole and its file size")


def main():
    start_time = None
    end_time = None

    elapsedTime = None

    elapsedMinutes = None
    elapsedSeconds = None

    WaitForInitialAutoanalysis()

    start_time = datetime.now().time().strftime('%H:%M:%S')

    fix_addresses()

    end_time = datetime.now().time().strftime('%H:%M:%S')

    elapsedTime = datetime.strptime(end_time, '%H:%M:%S') - datetime.strptime(start_time, '%H:%M:%S')

    elapsedMinutes = int(elapsedTime.total_seconds() / 60)
    elapsedSeconds = int(elapsedTime.total_seconds() - elapsedMinutes * 60)

    print("")
    print("successes:" + ' ' + str(successes))
    print("failures:" + ' ' + str(failures))

    print("")
    print("patched bytes:" + ' ' + str(patched_bytes))

    print("")
    print("matches between first segment to the segment before the memory hole:")
    print("first segment to segment before memory hole matches:" + ' ' + str(first_segment_to_segment_before_memhole_matches))
    print("suggested sequence bytes offset matches:" + ' ' + str(suggested_sequence_bytes_offset_matches))
    print("suggested sequence bytes offset mismatches:" + ' ' + str(suggested_sequence_bytes_offset_mismatches))
    print("suggested hardcore sequence bytes offset matches:" + ' ' + str(suggested_hardcore_sequence_bytes_offset_matches))
    print("suggested hardcore sequence bytes offset mismatches:" + ' ' + str(suggested_hardcore_sequence_bytes_offset_mismatches))

    print("")
    print("matches between the segment before the memory hole to the segment after the memory hole and its file size:")
    print(
        "segment before memory hole to segment after memory hole and its file size matches:"
        + ' ' + str(segment_before_memhole_to_segment_after_memhole_and_its_file_size_matches)
    )

    print("")
    print("elapsed time:" + ' ' + str(elapsedMinutes).zfill(2) + ':' + str(elapsedSeconds).zfill(2))

    print("")
    print("done")


main()
