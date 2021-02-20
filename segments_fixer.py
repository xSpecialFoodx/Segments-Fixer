import idc
import idautils
import idaapi

import winsound
from datetime import datetime
import time
import math
import string

#
# #
# # #
# # # # Segments Fixer
# # #
# #
#

# global variables (in python u dont really need to declare them, but just for clarifying)

# user input

dry_run = False
verbose = False
sound = False

FirstSegment_VirtualAddress = 0x00000000

SegmentBeforeMemHole_VirtualAddress = 0x00000000

SegmentAfterMemHole_Unmapped_VirtualAddress = 0x00000000
SegmentAfterMemHole_Mapped_VirtualAddress = 0x00000000
SegmentAfterMemHole_MemorySize = 0x00000000

# program input

# 000x: 0 - overwrite the sequence bytes offset if it's empty
#       1 - overwrite the sequence bytes offset even if it's not empty
# 00x0: 0 - do not overwrite using the suggested sequence bytes offset
#       1 - overwrite using the suggested sequence bytes offset if it's not empty
# 0x00: 0 - do not overwrite using the suggested hardcore sequence bytes offset
#       1 - overwrite using the suggested hardcore sequence bytes offset if it's not empty
# x000: 0 - prioritize suggested sequence bytes offset over suggested hardcore sequence bytes offset
#       1 - prioritize suggested hardcore sequence bytes offset over suggested sequence bytes offset

sequence_bytes_offset_use_options = int("0000", 2)

# goes for testing the suggested hardcore in generating the suggested offset itself not relying on any structure
suggested_hardcore_sequence_bytes_offset_test = False

# program variables (shouldn't be changed in most cases)

BytesLength = 2
SizesLength = 8
AddressesLength = 8

successes = 0
success_text = None

failures = 0
failure_text = None

patched_bytes = 0

first_segment_to_segment_before_memhole_matches = 0

heads = None
heads_amount = None
heads_index = None
previous_head = None
current_head = None
next_head = None

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

position = None

cs_structures = None
cs_address = None
cs_text = "cs:"  # code segment
cs_text_length = len(cs_text)

static_TP_structures = None
static_TP_text = "static_TP"
static_TP_text_length = len(static_TP_text)

mem_hole_size = SegmentAfterMemHole_Unmapped_VirtualAddress - SegmentAfterMemHole_Mapped_VirtualAddress

min_bytes_size = int(mem_hole_size)
min_bytes_amount = int(math.ceil(math.log(min_bytes_size, 0x00000100)))
min_bytes_estimated_amount = int(math.pow(2, int(math.ceil(math.log(min_bytes_amount, 2)))))

max_bytes_size = (
    int(math.pow(0x00000100, int(math.ceil(
        math.log(
            (SegmentAfterMemHole_Unmapped_VirtualAddress + SegmentAfterMemHole_MemorySize - 1) * 1.2, 0x00000100
        )  # multiplying by 1.2 because the hex bytes might be a big bigger than the last address, so doing it in order to stay on the safe zone
    )))) - 1
)  # for example, if its 0x00000500, it gets multiplied by 1.2 to 0x00000600, which is 2 bytes, so it goes to 0x0000FFFF which is the max number in 2 bytes

max_bytes_amount = int(math.ceil(math.log(max_bytes_size, 0x00000100)))
max_bytes_estimated_amount = int(math.pow(2, int(math.ceil(math.log(max_bytes_amount, 2)))))

safe_min_bytes_size = int(SegmentAfterMemHole_Unmapped_VirtualAddress)
safe_min_bytes_amount = int(math.ceil(math.log(safe_min_bytes_size, 0x00000100)))
safe_min_bytes_estimated_amount = int(math.pow(2, int(math.ceil(math.log(safe_min_bytes_amount, 2)))))

safe_max_bytes_size = int(SegmentAfterMemHole_Unmapped_VirtualAddress + SegmentAfterMemHole_MemorySize - 1)
safe_max_bytes_amount = int(math.ceil(math.log(safe_max_bytes_size, 0x00000100)))
safe_max_bytes_estimated_amount = int(math.pow(2, int(math.ceil(math.log(safe_max_bytes_amount, 2)))))

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


def CheckBinText(source, length, add_0b):  # returns the binary text
    source_bin = str(bin(source)[2:])
    source_bin_length = len(source_bin)
    source_bin_index = None
    source_bin_cell = None

    for source_bin_index in range(0, source_bin_length):
        source_bin_cell = source_bin[source_bin_index]

        if (
            source_bin_cell == "0"
            or source_bin_cell == "1"
        ) is False:
            source_bin = source_bin[:source_bin_index]

            break

    result = str(source_bin.zfill(length))

    if add_0b is True:
        result = "0b" + result

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


def WaitForInitialAutoanalysis():
    idc.auto_wait()


def CompletionSound():
    frequencies = [420, 430, 440]
    frequency = None

    duration = 500

    for frequency in frequencies:
        winsound.Beep(frequency, duration)
        time.sleep(duration / 1000)


def CheckHeads(start_address, end_address):  # returns the heads in the range
    result = None

    current_result = []

    heads = idautils.Heads(start_address, end_address)

    for head in heads:
        current_result.append(int(head))

    result = current_result

    return result


def CheckCommand(address):  # returns the command
    result = str(idc.GetDisasm(address))

    return result


def CheckByte(address):  # returns the byte from the address
    result = int(idc.GetOriginalByte(address))

    return result


def ApplyByte(address, byte):  # applies the byte in the adddress
    idc.PatchByte(address, byte)


def CheckSequenceBytesAmount(sequence_bytes_address):  # returns the sequence bytes amount
    result = None

    current_result = int(idc.ItemSize(sequence_bytes_address))

    if current_result <= 0:
        current_result = 1

    result = current_result

    return result


def CheckSequencesBytesAddresses(start_address, end_address):  # returns the sequences bytes addresses in the range
    result = None

    current_result = []

    sequence_bytes_address = start_address
    sequence_bytes_amount = None

    while sequence_bytes_address <= end_address:
        current_result.append(sequence_bytes_address)

        sequence_bytes_amount = CheckSequenceBytesAmount(sequence_bytes_address)

        sequence_bytes_address += sequence_bytes_amount

    result = current_result

    return result


def CreateSequence(address, amount):  # returns True if succeed to create the sequence, False if didn't
    # if the amount is None then checking the sequence amount using the CheckSequenceBytesAmount function

    result = None

    # Global Variables

    # global dry_run
    # global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

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

    # global position

    # global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    # global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    # global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    # global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

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
            sequence_bytes_amount = CheckSequenceBytesAmount(sequence_bytes_address)

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
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

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

    # global position

    # global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    # global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    # global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    # global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

    global sequence_bytes
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

    if offset >= 0 and offset < sequence_bytes_amount:
        if sequence_bytes[offset] is not None:
            current_result = sequence_bytes[offset]
        else:
            current_result = CheckByte(sequence_bytes_address + offset)

            sequence_bytes[offset] = current_result

    result = current_result

    return result


def CheckSequenceBytes(offset, amount, min_size, max_size):  # returns True if the original bytes size is in range, False if it isn't
    # set min or max as 0 or below in order to have them disabled

    result = None

    # Global Variables

    # global dry_run
    # global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

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

    # global position

    # global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    # global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount

    global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    # global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    # global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

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
                if min_size > max_bytes_size:
                    current_min_bytes_size = max_bytes_size
                else:
                    current_min_bytes_size = min_size

        if max_size <= 0:
            current_max_bytes_size = max_bytes_size
        else:
            if max_size > max_bytes_size:
                current_max_bytes_size = max_bytes_size
            else:
                if max_size < min_bytes_size:
                    current_max_bytes_size = min_bytes_size
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
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

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

    # global position

    # global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    # global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    # global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    # global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

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

        CheckSequenceByte(offset)  # no need to check the result, as we'll check the sequence bytes directly

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
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

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

    # global position

    # global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    # global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    # global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    # global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

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

        # no need to check if the result is True because if it doesn't so it's just not patching it

        PatchSequenceByte(offset + fixed_bytes_index, fixed_byte)

        # print(CheckHexText(fixed_byte, BytesLength, True))


def CheckSequenceBytesText(direction):  # returns the sequence bytes text, None in case of not finding any
    # gets direction, True goes for first to last byte, False goes for last to first byte

    result = None

    # Global Variables

    # global dry_run
    # global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

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

    # global position

    # global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    # global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    # global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    # global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

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
        if direction is True:
            sequence_bytes_index = 0
        else:
            sequence_bytes_index = sequence_bytes_amount - 1

        while (
            direction is True and sequence_bytes_index < sequence_bytes_amount
            or direction is False and sequence_bytes_index >= 0
        ):
            sequence_byte = CheckSequenceByte(sequence_bytes_index)

            if sequence_byte is not None:
                if current_result is None:
                    current_result = ""

                current_result += CheckHexText(sequence_byte, BytesLength, (current_result == ""))
            else:
                break

            if direction is True:
                sequence_bytes_index += 1
            else:
                sequence_bytes_index -= 1

    result = current_result

    return result


def CreateStructure(
    sequence_bytes_offsets_mode
    , sequence_bytes_offsets
    , cmd_position_offset
    , cmd_fixed_splitted_min_amount
    , cmd_fixed_splitted_max_amount
    , command
    , typeA
    , typeB
    , typeC
    , typeD
    , typeE
):  # returns the new structure
    # structure cells:
    # 0 - sequence bytes offsets mode
    # 1 - sequence bytes offsets
    # 2 - cmd position offset (from the end of cmd_fixed_splitted_amount)
    # 3 - cmd fixed splitted min amount
    # 4 - cmd fixed splitted max amount
    # 5 - command
    # 6 - typeA
    # 7 - typeB
    # 8 - typeC
    # 9 - typeD
    # 10 - typeE

    # sequence bytes offsets mode options:
    # 00x:  0 - don't apply it to the sequence bytes offset
    #       1 - apply it to the sequence bytes offset
    # 0x0:  0 - don't apply it to the suggested sequence bytes offset
    #       1 - apply it to the suggested sequence bytes offset
    # x00:  0 - don't apply it to the suggested hardcore sequence bytes offset
    #       1 - apply it to the suggested hardcore sequence bytes offset

    result = (
        [
            sequence_bytes_offsets_mode
            , sequence_bytes_offsets
            , cmd_position_offset
            , cmd_fixed_splitted_min_amount
            , cmd_fixed_splitted_max_amount
            , command
            , typeA
            , typeB
            , typeC
            , typeD
            , typeE
        ]
    )

    return result


def CreateStructures():
    # each structures is an array of structure arrays, each structure is an array, set cells as None in order to skip them

    # Global Variables

    # global dry_run
    # global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

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

    # global position

    global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    # global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    # global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

    # global sequence_bytes
    # global sequence_bytes_address
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

    if cs_structures is None:
        cs_structures = (
            [
                CreateStructure(int("111", 2), [0], 0, 3, 3, "add", None, None, None, None, None)
                , CreateStructure(int("111", 2), [0], 0, 3, 3, "and", None, None, None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "call", "qword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 0, 3, 3, "cmp", None, None, None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "dec", "qword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "dec", "dword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "div", "dword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "fld", "tbyte", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "idiv", "dword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "inc", "qword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "inc", "dword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "inc", "word", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "jmp", "qword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 0, 3, 3, "lea", None, None, None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "lock", "dec", "dword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "lock", "inc", "dword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "lock", "xchg", None, None, None, None)
                , CreateStructure(int("111", 2), [0], 0, 3, 3, "mov", None, None, None, None, None)
                , CreateStructure(int("111", 2), [0], 0, 3, 3, "movbe", None, None, None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "movsx", None, "byte", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "movsxd", None, "dword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "movzx", None, "byte", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "movzx", None, "word", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, 3, 3, "or", None, None, None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "setz", "byte", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 0, 3, 3, "sub", None, None, None, None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vaddps", None, None, "xmmword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vaddsd", None, None, "qword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vaddss", None, None, "dword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vandps", None, None, "xmmword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vbroadcastsd", None, "qword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vbroadcastss", None, "dword", "ptr", None, None)
                , CreateStructure(int("111", 2), [1], 0, None, None, "vcmpeqss", None, None, "dword", "ptr", None)
                , CreateStructure(int("111", 2), [1], 0, None, None, "vcmpltps", None, None, "xmmword", "ptr", None)
                , CreateStructure(int("111", 2), [1], 0, None, None, "vcmpltss", None, None, "dword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vcvtsi2sd", None, None, "qword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vcvtsi2ss", None, None, "dword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vcvttss2si", None, "dword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vdivss", None, None, "dword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmaxps", None, None, "xmmword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmaxss", None, None, "dword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vminps", None, None, "xmmword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vminss", None, None, "dword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmovd", None, "dword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmovdqu", None, "xmmword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmovdqu", None, "ymmword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmovhpd", None, None, "qword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmovq", None, "qword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmovsd", None, "qword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmovss", None, "dword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmovupd", None, "xmmword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmovups", None, "xmmword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmovups", None, "ymmword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmulps", None, None, "xmmword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmulsd", None, None, "qword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vmulss", None, None, "dword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vpand", None, None, "xmmword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vsubsd", None, None, "qword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vsubss", None, None, "dword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 0, None, None, "vucomiss", None, "dword", "ptr", None, None)
                , CreateStructure(int("111", 2), [0], 0, 3, 3, "xchg", None, None, None, None, None)
                , CreateStructure(int("111", 2), [0], 0, 3, 3, "xor", None, None, None, None, None)
                , CreateStructure(int("111", 2), [0], 1, 3, 3, "add", None, None, None, None, None)
                , CreateStructure(int("111", 2), [1], 1, None, None, "add", "dword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, 3, 3, "and", None, None, None, None, None)
                , CreateStructure(int("111", 2), [1], 1, None, None, "and", "qword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [4], 1, None, None, "and", "dword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [1], 1, None, None, "and", "byte", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, 4, 4, "bextr", None, None, None, None, None)
                , CreateStructure(int("111", 2), [0], 1, 3, 3, "cmp", None, None, None, None, None)
                , CreateStructure(int("111", 2), [1], 1, None, None, "cmp", "qword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [1, 4], 1, None, None, "cmp", "dword", "ptr", None, None, None)  # not 100% safe
                , CreateStructure(int("111", 2), [1], 1, None, None, "cmp", "byte", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "lock", "add", None, None, None, None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "lock", "cmpxchg", None, None, None, None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "lock", "xadd", None, None, None, None)
                , CreateStructure(int("111", 2), [0], 1, 3, 3, "mov", None, None, None, None, None)
                , CreateStructure(int("111", 2), [4], 1, None, None, "mov", "qword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [4], 1, None, None, "mov", "dword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [2], 1, None, None, "mov", "word", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [1], 1, None, None, "mov", "byte", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [1], 1, None, None, "or", "byte", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, 3, 3, "sub", None, None, None, None, None)
                , CreateStructure(int("111", 2), [1], 1, None, None, "test", "byte", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [4], 1, None, None, "test", "dword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [1], 1, None, None, "vinsertps", None, None, "dword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "vmovdqu", "xmmword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "vmovdqu", "ymmword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "vmovlpd", "qword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "vmovlps", "qword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "vmovsd", "qword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "vmovss", "dword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "vmovupd", "xmmword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "vmovups", "xmmword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [0], 1, None, None, "vmovups", "ymmword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [1], 1, None, None, "vpinsrq", None, None, "qword", "ptr", None)
                , CreateStructure(int("111", 2), [0], 1, 3, 3, "xor", None, None, None, None, None)
                , CreateStructure(int("111", 2), [4], 2, None, None, "mov", "qword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [4], 2, None, None, "mov", "dword", "ptr", None, None, None)
                , CreateStructure(int("111", 2), [1], 2, None, None, "vextractps", "dword", "ptr", None, None, None)
            ]
        )

    if static_TP_structures is None:
        static_TP_structures = (
            [
                CreateStructure(int("111", 2), [0], 0, 3, 3, "lea", None, None, None, None, None)
            ]
        )


def CombineStructures():
    # Global Variables

    # global dry_run
    # global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

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

    # global position

    global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    # global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    # global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

    # global sequence_bytes
    # global sequence_bytes_address
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

    structures_list = [cs_structures, static_TP_structures]
    structures_list_amount = len(structures_list)
    structures_list_indexA = None
    structures_list_indexB = None

    structuresA = None
    structureA = None
    structureA_amount = None
    structureA_index = None
    structureA_cell = None

    structureA_sequence_bytes_offsets_mode = None
    structureA_fixed_sequence_bytes_offsets_mode = None
    structureA_sequence_bytes_offsets = None
    structureA_sequence_bytes_offset = None

    structuresB = None
    structureB = None
    structureB_amount = None
    structureB_cell = None

    structureB_sequence_bytes_offsets_mode = None
    structureB_sequence_bytes_offsets = None
    structureB_sequence_bytes_offset = None

    method_found = False
    error_found = False

    # Start

    for structures_list_indexA in range(0, structures_list_amount):
        structuresA = structures_list[structures_list_indexA]

        for structures_list_indexB in range(0, structures_list_amount):
            structuresB = structures_list[structures_list_indexB]

            if structuresA != structuresB:
                for structureA in structuresA:
                    structureA_amount = len(structureA)

                    if structureA_amount >= 2:
                        structureA_sequence_bytes_offsets_mode = structureA[0]

                        structureA_fixed_sequence_bytes_offsets_mode = (
                            (structureA_sequence_bytes_offsets_mode & int("110", 2))
                            if (structureA_sequence_bytes_offsets_mode & int("001", 2)) > 0
                            else structureA_sequence_bytes_offsets_mode
                        )  # don't apply the combination to the original sequence bytes offset, but only to the suggested ones

                        structureA_sequence_bytes_offsets = structureA[1]

                        for structureB in structuresB:
                            structureB_amount = len(structureB)

                            if structureA_amount != structureB_amount:
                                error_found = True
                            else:
                                structureB_sequence_bytes_offsets_mode = structureB[0]
                                structureB_sequence_bytes_offsets = structureB[1]

                                for structureA_index in range(2, structureA_amount):
                                    structureA_cell = structureA[structureA_index]

                                    structureB_cell = structureB[structureA_index]

                                    if structureA_cell != structureB_cell:
                                        error_found = True

                                        break

                                if error_found is False:
                                    if (
                                        (structureA_fixed_sequence_bytes_offsets_mode | structureB_sequence_bytes_offsets_mode)
                                        > structureB_sequence_bytes_offsets_mode
                                    ):  # means that it adds an option that it doesn't have at the moment
                                        error_found = True
                                    elif structureA_fixed_sequence_bytes_offsets_mode == structureB_sequence_bytes_offsets_mode:  # checking the offsets
                                        for structureA_sequence_bytes_offset in structureA_sequence_bytes_offsets:
                                            for structureB_sequence_bytes_offset in structureB_sequence_bytes_offsets:
                                                if structureA_sequence_bytes_offset == structureB_sequence_bytes_offset:
                                                    error_found = True

                                                    break

                                            if error_found is True:
                                                error_found = False
                                            else:
                                                structureB_sequence_bytes_offsets.append(structureA_sequence_bytes_offset)

                            if error_found is True:
                                error_found = False
                            else:
                                method_found = True

                                break

                        if method_found is True:
                            method_found = False
                        else:
                            structureB = []

                            structuresB.append(structureB)

                            structureA_cell = structureA_fixed_sequence_bytes_offsets_mode

                            structureB_cell = structureA_cell

                            structureB.append(structureB_cell)

                            for structureA_index in range(1, structureA_amount):
                                structureA_cell = structureA[structureA_index]

                                structureB_cell = structureA_cell

                                structureB.append(structureB_cell)


def TestSequenceBytesOffset(offsets, min_size, max_size):
    # returns the offset from the offsets that fits the demands
    # (returns None if couldn't find any)

    # set min or max as 0 or below in order to ignore them

    result = None

    # Global Variables

    # global dry_run
    # global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

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

    # global position

    # global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    # global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    global min_bytes_size
    global min_bytes_amount
    global min_bytes_estimated_amount

    global max_bytes_size
    global max_bytes_amount
    global max_bytes_estimated_amount

    global safe_min_bytes_size
    global safe_min_bytes_amount
    global safe_min_bytes_estimated_amount

    global safe_max_bytes_size
    global safe_max_bytes_amount
    global safe_max_bytes_estimated_amount

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

    current_result = None

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

    offset = None

    method_found = False
    error_found = False

    # Start

    if min_size <= 0:
        current_min_bytes_size = min_bytes_size
    else:
        if min_size < min_bytes_size:
            current_min_bytes_size = min_bytes_size
        else:
            if min_size > max_bytes_size:
                current_min_bytes_size = max_bytes_size
            else:
                current_min_bytes_size = min_size

    if current_min_bytes_size == min_bytes_size:
        current_min_bytes_amount = min_bytes_amount
        current_min_bytes_estimated_amount = min_bytes_estimated_amount
    elif current_min_bytes_size == max_bytes_size:
        current_min_bytes_amount = max_bytes_amount
        current_min_bytes_estimated_amount = max_bytes_estimated_amount
    elif current_min_bytes_size == safe_min_bytes_size:
        current_min_bytes_amount = safe_min_bytes_amount
        current_min_bytes_estimated_amount = safe_min_bytes_estimated_amount
    elif current_min_bytes_size == safe_max_bytes_size:
        current_min_bytes_amount = safe_max_bytes_amount
        current_min_bytes_estimated_amount = safe_max_bytes_estimated_amount
    else:
        current_min_bytes_amount = int(math.ceil(math.log(current_min_bytes_size, 0x00000100)))

        if current_min_bytes_amount == min_bytes_amount:
            current_min_bytes_estimated_amount = min_bytes_estimated_amount
        elif current_min_bytes_amount == max_bytes_amount:
            current_min_bytes_estimated_amount = max_bytes_estimated_amount
        else:
            current_min_bytes_estimated_amount = int(math.pow(2, int(math.ceil(math.log(current_min_bytes_amount, 2)))))

    if max_size <= 0:
        current_max_bytes_size = max_bytes_size
    else:
        if max_size > max_bytes_size:
            current_max_bytes_size = max_bytes_size
        else:
            if max_size < min_bytes_size:
                current_max_bytes_size = min_bytes_size
            else:
                current_max_bytes_size = max_size

    if current_max_bytes_size == max_bytes_size:
        current_max_bytes_amount = max_bytes_amount
        current_max_bytes_estimated_amount = max_bytes_estimated_amount
    elif current_max_bytes_size == min_bytes_size:
        current_max_bytes_amount = min_bytes_amount
        current_max_bytes_estimated_amount = min_bytes_estimated_amount
    elif current_max_bytes_size == safe_max_bytes_size:
        current_max_bytes_amount = safe_max_bytes_amount
        current_max_bytes_estimated_amount = safe_max_bytes_estimated_amount
    elif current_max_bytes_size == safe_min_bytes_size:
        current_max_bytes_amount = safe_min_bytes_amount
        current_max_bytes_estimated_amount = safe_min_bytes_estimated_amount
    else:
        current_max_bytes_amount = int(math.ceil(math.log(current_max_bytes_size, 0x00000100)))

        if current_max_bytes_amount == min_bytes_amount:
            current_max_bytes_estimated_amount = min_bytes_estimated_amount
        elif current_max_bytes_amount == max_bytes_amount:
            current_max_bytes_estimated_amount = max_bytes_estimated_amount
        else:
            current_max_bytes_estimated_amount = int(math.pow(2, int(math.ceil(math.log(current_max_bytes_amount, 2)))))

    current_bytes_amount = current_min_bytes_amount

    while current_bytes_amount <= current_max_bytes_amount:
        for offset in offsets:
            if sequence_bytes_amount > offset:
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
                        current_result = offset

                        method_found = True

                        break

        if method_found is True:
            break

        current_bytes_amount += 1

    result = current_result

    return result


def CheckSequenceBytesOffset(structures):  # returns True if found a suitable sequence bytes offset, False if didn't
    result = None

    # Global Variables

    # global dry_run
    # global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    global sequence_bytes_offset_use_options

    global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global patched_bytes

    global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    global previous_head
    global current_head
    global next_head

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

    global position

    # global cs_structures
    global cs_address
    # global cs_text
    # global cs_text_length

    # global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

    # global sequence_bytes
    global sequence_bytes_address
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

    last_position = (position == cmd_fixed_splitted_amount)

    previous_address = None
    current_address = (current_head if current_head is not None else sequence_bytes_address)
    next_address = None

    min_size = None
    max_size = None

    safe_min_size = None
    safe_max_size = None

    structure = None
    structure_sequence_bytes_offsets_mode = None
    structure_sequence_bytes_offsets = None
    structure_cmd_position_offset = None
    structure_cmd_fixed_splitted_min_amount = None
    structure_cmd_fixed_splitted_max_amount = None
    structure_command = None
    structure_typeA = None
    structure_typeB = None
    structure_typeC = None
    structure_typeD = None
    structure_typeE = None

    structure_sequence_bytes_offsets_mode_apply_sequence_bytes_offset = None
    structure_sequence_bytes_offsets_mode_apply_suggested_sequence_bytes_offset = None
    structure_sequence_bytes_offsets_mode_apply_suggested_hardcore_sequence_bytes_offset = None

    command = None
    typeA = None
    typeB = None
    typeC = None
    typeD = None
    typeE = None

    sequence_bytes_offsets = None
    sequence_bytes_offsets_level = 0

    suggested_sequence_bytes_offsets = None
    suggested_sequence_bytes_offsets_level = 0

    suggested_hardcore_sequence_bytes_offsets = None
    suggested_hardcore_sequence_bytes_offsets_level = 0

    overwrite_sequence_bytes_offset = None

    offsets = None
    offsets_used = None
    offset = None

    last_position_offsets = None
    last_position_offset = None

    not_last_position_offsets = None
    not_last_position_offset = None

    method_found = False

    # Start

    sequence_bytes_offset = None

    suggested_sequence_bytes_offset = None

    suggested_hardcore_sequence_bytes_offset = None

    previous_address = ((previous_head - 0x00000100) if previous_head is not None else (current_address - 0x00001000))
    next_address = ((next_head + 0x00000100) if next_head is not None else (current_address + 0x00001000))

    safe_min_size = safe_min_bytes_size - next_address
    safe_max_size = safe_max_bytes_size - previous_address

    if cs_address is not None:
        min_size = cs_address - next_address
        max_size = cs_address - previous_address
    else:
        min_size = safe_min_size
        max_size = safe_max_size

        safe_min_size = None
        safe_max_size = None

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
        structure_sequence_bytes_offsets_mode = structure[0]
        structure_sequence_bytes_offsets = structure[1]
        structure_cmd_position_offset = structure[2]
        structure_cmd_fixed_splitted_min_amount = structure[3]
        structure_cmd_fixed_splitted_max_amount = structure[4]
        structure_command = structure[5]
        structure_typeA = structure[6]
        structure_typeB = structure[7]
        structure_typeC = structure[8]
        structure_typeD = structure[9]
        structure_typeE = structure[10]

        if (
            structure_cmd_position_offset is None
            or position == cmd_fixed_splitted_amount - structure_cmd_position_offset
        ):
            if structure_command is None or command is not None and command == structure_command:
                structure_sequence_bytes_offsets_mode_apply_sequence_bytes_offset = (
                    (structure_sequence_bytes_offsets_mode & int("001", 2)) > 0
                )

                structure_sequence_bytes_offsets_mode_apply_suggested_sequence_bytes_offset = (
                    (structure_sequence_bytes_offsets_mode & int("010", 2)) > 0
                )

                structure_sequence_bytes_offsets_mode_apply_suggested_hardcore_sequence_bytes_offset = (
                    (structure_sequence_bytes_offsets_mode & int("100", 2)) > 0
                )

                if structure_cmd_fixed_splitted_min_amount is None or cmd_fixed_splitted_amount >= structure_cmd_fixed_splitted_min_amount:
                    if structure_cmd_fixed_splitted_max_amount is None or cmd_fixed_splitted_amount <= structure_cmd_fixed_splitted_max_amount:
                        if structure_typeA is None or typeA is not None and typeA == structure_typeA:
                            if structure_typeB is None or typeB is not None and typeB == structure_typeB:
                                if structure_typeC is None or typeC is not None and typeC == structure_typeC:
                                    if structure_typeD is None or typeD is not None and typeD == structure_typeD:
                                        if structure_typeE is None or typeE is not None and typeE == structure_typeE:
                                            if sequence_bytes_offsets_level < 8:
                                                if structure_sequence_bytes_offsets_mode_apply_sequence_bytes_offset is True:
                                                    sequence_bytes_offsets = structure_sequence_bytes_offsets

                                                sequence_bytes_offsets_level = 8

                                            if suggested_sequence_bytes_offsets_level < 8:
                                                if structure_sequence_bytes_offsets_mode_apply_suggested_sequence_bytes_offset is True:
                                                    suggested_sequence_bytes_offsets = structure_sequence_bytes_offsets

                                                suggested_sequence_bytes_offsets_level = 8

                                            if suggested_hardcore_sequence_bytes_offsets_level < 8:
                                                if structure_sequence_bytes_offsets_mode_apply_suggested_hardcore_sequence_bytes_offset is True:
                                                    suggested_hardcore_sequence_bytes_offsets = structure_sequence_bytes_offsets

                                                suggested_hardcore_sequence_bytes_offsets_level = 8
                                        else:
                                            if suggested_sequence_bytes_offsets_level < 7:
                                                if structure_sequence_bytes_offsets_mode_apply_suggested_sequence_bytes_offset is True:
                                                    suggested_sequence_bytes_offsets = structure_sequence_bytes_offsets

                                                suggested_sequence_bytes_offsets_level = 7

                                            if suggested_hardcore_sequence_bytes_offsets_level < 7:
                                                if structure_sequence_bytes_offsets_mode_apply_suggested_hardcore_sequence_bytes_offset is True:
                                                    suggested_hardcore_sequence_bytes_offsets = structure_sequence_bytes_offsets

                                                suggested_hardcore_sequence_bytes_offsets_level = 7
                                    else:
                                        if suggested_sequence_bytes_offsets_level < 6:
                                            if structure_sequence_bytes_offsets_mode_apply_suggested_sequence_bytes_offset is True:
                                                suggested_sequence_bytes_offsets = structure_sequence_bytes_offsets

                                            suggested_sequence_bytes_offsets_level = 6

                                        if suggested_hardcore_sequence_bytes_offsets_level < 6:
                                            if structure_sequence_bytes_offsets_mode_apply_suggested_hardcore_sequence_bytes_offset is True:
                                                suggested_hardcore_sequence_bytes_offsets = structure_sequence_bytes_offsets

                                            suggested_hardcore_sequence_bytes_offsets_level = 6
                                else:
                                    if suggested_sequence_bytes_offsets_level < 5:
                                        if structure_sequence_bytes_offsets_mode_apply_suggested_sequence_bytes_offset is True:
                                            suggested_sequence_bytes_offsets = structure_sequence_bytes_offsets

                                        suggested_sequence_bytes_offsets_level = 5

                                    if suggested_hardcore_sequence_bytes_offsets_level < 5:
                                        if structure_sequence_bytes_offsets_mode_apply_suggested_hardcore_sequence_bytes_offset is True:
                                            suggested_hardcore_sequence_bytes_offsets = structure_sequence_bytes_offsets

                                        suggested_hardcore_sequence_bytes_offsets_level = 5
                            else:
                                if suggested_sequence_bytes_offsets_level < 4:
                                    if structure_sequence_bytes_offsets_mode_apply_suggested_sequence_bytes_offset is True:
                                        suggested_sequence_bytes_offsets = structure_sequence_bytes_offsets

                                    suggested_sequence_bytes_offsets_level = 4

                                if suggested_hardcore_sequence_bytes_offsets_level < 4:
                                    if structure_sequence_bytes_offsets_mode_apply_suggested_hardcore_sequence_bytes_offset is True:
                                        suggested_hardcore_sequence_bytes_offsets = structure_sequence_bytes_offsets

                                    suggested_hardcore_sequence_bytes_offsets_level = 4
                        else:
                            if suggested_hardcore_sequence_bytes_offsets_level < 3:
                                if structure_sequence_bytes_offsets_mode_apply_suggested_hardcore_sequence_bytes_offset is True:
                                    suggested_hardcore_sequence_bytes_offsets = structure_sequence_bytes_offsets

                                suggested_hardcore_sequence_bytes_offsets_level = 3
                    else:
                        if suggested_hardcore_sequence_bytes_offsets_level < 2:
                            if structure_sequence_bytes_offsets_mode_apply_suggested_hardcore_sequence_bytes_offset is True:
                                suggested_hardcore_sequence_bytes_offsets = structure_sequence_bytes_offsets

                            suggested_hardcore_sequence_bytes_offsets_level = 2
                else:
                    if suggested_hardcore_sequence_bytes_offsets_level < 1:
                        if structure_sequence_bytes_offsets_mode_apply_suggested_hardcore_sequence_bytes_offset is True:
                            suggested_hardcore_sequence_bytes_offsets = structure_sequence_bytes_offsets

                        suggested_hardcore_sequence_bytes_offsets_level = 1

        if (
            sequence_bytes_offsets_level == 8
            and suggested_sequence_bytes_offsets_level == 8
            and suggested_hardcore_sequence_bytes_offsets_level == 8
        ):
            break

    if sequence_bytes_offsets is not None:
        offsets = sequence_bytes_offsets
        offset = TestSequenceBytesOffset(offsets, min_size, max_size)

        # if offset is None:  # can uncomment these lines if you face problems
        #     if safe_min_size is not None and safe_max_size is not None:
        #         offset = TestSequenceBytesOffset(offsets, safe_min_size, safe_max_size)
        #
        #     if offset is None:
        #         offset = TestSequenceBytesOffset(offsets, -1, -1)

        if offset is not None:
            sequence_bytes_offset = offset

    if suggested_sequence_bytes_offsets is not None:
        offsets = suggested_sequence_bytes_offsets
        offset = TestSequenceBytesOffset(offsets, min_size, max_size)

        if offset is None:  # can comment these lines if you face problems
            if safe_min_size is not None and safe_max_size is not None:
                offset = TestSequenceBytesOffset(offsets, safe_min_size, safe_max_size)

            if offset is None:
                offset = TestSequenceBytesOffset(offsets, -1, -1)

        if offset is not None:
            suggested_sequence_bytes_offset = offset

    if suggested_hardcore_sequence_bytes_offsets is not None:
        if suggested_hardcore_sequence_bytes_offset_test is False:
            offsets = suggested_hardcore_sequence_bytes_offsets
            offset = TestSequenceBytesOffset(offsets, min_size, max_size)
        else:
            offsets = None
            offset = None
    else:
        offsets = None
        offset = None

    if offset is None:
        if offsets is not None:
            offsets_used = offsets
        else:
            offsets_used = []

        offsets = []

        last_position_offsets = (
            [
                0
                # , 1
                # , 2
                # , 3  # haven't seen
                # , 4  # haven't seen
                # , 5  # haven't seen
                # , 6  # haven't seen
                # , 7  # haven't seen
                # , 8  # haven't seen
                # , 9  # haven't seen
                # , 10  # haven't seen
                # , 11  # haven't seen
                # , 12  # haven't seen
                # , 13  # haven't seen
                # , 14  # haven't seen
                # , 15  # haven't seen
                # , 16  # haven't seen
            ]
        )

        last_position_offset = None

        not_last_position_offsets = (
            [
                # 16  # haven't seen
                # , 15  # haven't seen
                # , 14  # haven't seen
                # , 13  # haven't seen
                # , 12  # haven't seen
                # , 11  # haven't seen
                # , 10  # haven't seen
                # , 9  # haven't seen
                # , 8  # haven't seen
                # , 7  # haven't seen
                # , 6  # haven't seen
                # , 5  # haven't seen
                # , 4
                # , 3  # haven't seen
                # , 2
                1
                , 0
            ]
        )

        not_last_position_offset = None

        if last_position is True:
            for last_position_offset in last_position_offsets:
                if (last_position_offset in offsets_used) is False:
                    offset = last_position_offset

                    offsets.append(offset)
                    offsets_used.append(offset)

                    if method_found is False:
                        method_found = True
        else:
            for not_last_position_offset in not_last_position_offsets:
                if (not_last_position_offset in offsets_used) is False:
                    offset = not_last_position_offset

                    offsets.append(offset)
                    offsets_used.append(offset)

                    if method_found is False:
                        method_found = True

        if method_found is True:
            method_found = False

            offset = TestSequenceBytesOffset(offsets, min_size, max_size)

        if offset is None:
            offsets = []

            last_position_offsets = (
                [
                    # 0
                    1
                    # , 2
                    # , 3  # haven't seen
                    # , 4  # haven't seen
                    # , 5  # haven't seen
                    # , 6  # haven't seen
                    # , 7  # haven't seen
                    # , 8  # haven't seen
                    # , 9  # haven't seen
                    # , 10  # haven't seen
                    # , 11  # haven't seen
                    # , 12  # haven't seen
                    # , 13  # haven't seen
                    # , 14  # haven't seen
                    # , 15  # haven't seen
                    # , 16  # haven't seen
                ]
            )

            last_position_offset = None

            not_last_position_offsets = (
                [
                    # 16  # haven't seen
                    # , 15  # haven't seen
                    # , 14  # haven't seen
                    # , 13  # haven't seen
                    # , 12  # haven't seen
                    # , 11  # haven't seen
                    # , 10  # haven't seen
                    # , 9  # haven't seen
                    # , 8  # haven't seen
                    # , 7  # haven't seen
                    # , 6  # haven't seen
                    # , 5  # haven't seen
                    4
                    # , 3  # haven't seen
                    # , 2
                    # , 1
                    # , 0
                ]
            )

            not_last_position_offset = None

            if last_position is True:
                for last_position_offset in last_position_offsets:
                    if (last_position_offset in offsets_used) is False:
                        offset = last_position_offset

                        offsets.append(offset)
                        offsets_used.append(offset)

                        if method_found is False:
                            method_found = True
            else:
                for not_last_position_offset in not_last_position_offsets:
                    if (not_last_position_offset in offsets_used) is False:
                        offset = not_last_position_offset

                        offsets.append(offset)
                        offsets_used.append(offset)

                        if method_found is False:
                            method_found = True

            if method_found is True:
                method_found = False

                offset = TestSequenceBytesOffset(offsets, min_size, max_size)

            if offset is None:
                offsets = []

                last_position_offsets = (
                    [
                        # 0
                        # , 1
                        2
                        # , 3  # haven't seen
                        # , 4  # haven't seen
                        # , 5  # haven't seen
                        # , 6  # haven't seen
                        # , 7  # haven't seen
                        # , 8  # haven't seen
                        # , 9  # haven't seen
                        # , 10  # haven't seen
                        # , 11  # haven't seen
                        # , 12  # haven't seen
                        # , 13  # haven't seen
                        # , 14  # haven't seen
                        # , 15  # haven't seen
                        # , 16  # haven't seen
                    ]
                )

                last_position_offset = None

                not_last_position_offsets = (
                    [
                        # 16  # haven't seen
                        # , 15  # haven't seen
                        # , 14  # haven't seen
                        # , 13  # haven't seen
                        # , 12  # haven't seen
                        # , 11  # haven't seen
                        # , 10  # haven't seen
                        # , 9  # haven't seen
                        # , 8  # haven't seen
                        # , 7  # haven't seen
                        # , 6  # haven't seen
                        # , 5  # haven't seen
                        # , 4
                        # , 3  # haven't seen
                        2
                        # , 1
                        # , 0
                    ]
                )

                not_last_position_offset = None

                if last_position is True:
                    for last_position_offset in last_position_offsets:
                        if (last_position_offset in offsets_used) is False:
                            offset = last_position_offset

                            offsets.append(offset)
                            offsets_used.append(offset)

                            if method_found is False:
                                method_found = True
                else:
                    for not_last_position_offset in not_last_position_offsets:
                        if (not_last_position_offset in offsets_used) is False:
                            offset = not_last_position_offset

                            offsets.append(offset)
                            offsets_used.append(offset)

                            if method_found is False:
                                method_found = True

                if method_found is True:
                    method_found = False

                    offset = TestSequenceBytesOffset(offsets, min_size, max_size)

                if offset is None:
                    offsets = []

                    last_position_offsets = (
                        [
                            # 0
                            # , 1
                            # , 2
                            3  # haven't seen
                            , 4  # haven't seen
                            , 5  # haven't seen
                            , 6  # haven't seen
                            , 7  # haven't seen
                            , 8  # haven't seen
                            , 9  # haven't seen
                            , 10  # haven't seen
                            , 11  # haven't seen
                            , 12  # haven't seen
                            , 13  # haven't seen
                            , 14  # haven't seen
                            , 15  # haven't seen
                            , 16  # haven't seen
                        ]
                    )

                    last_position_offset = None

                    not_last_position_offsets = (
                        [
                            16  # haven't seen
                            , 15  # haven't seen
                            , 14  # haven't seen
                            , 13  # haven't seen
                            , 12  # haven't seen
                            , 11  # haven't seen
                            , 10  # haven't seen
                            , 9  # haven't seen
                            , 8  # haven't seen
                            , 7  # haven't seen
                            , 6  # haven't seen
                            , 5  # haven't seen
                            # , 4
                            , 3  # haven't seen
                            # , 2
                            # , 1
                            # , 0
                        ]
                    )

                    not_last_position_offset = None

                    if last_position is True:
                        for last_position_offset in last_position_offsets:
                            if (last_position_offset in offsets_used) is False:
                                offset = last_position_offset

                                offsets.append(offset)
                                offsets_used.append(offset)

                                if method_found is False:
                                    method_found = True
                    else:
                        for not_last_position_offset in not_last_position_offsets:
                            if (not_last_position_offset in offsets_used) is False:
                                offset = not_last_position_offset

                                offsets.append(offset)
                                offsets_used.append(offset)

                                if method_found is False:
                                    method_found = True

                    if method_found is True:
                        method_found = False

                        offset = TestSequenceBytesOffset(offsets, min_size, max_size)

                    if offset is None:  # can comment these lines if you face problems
                        offsets = offsets_used

                        if safe_min_size is not None and safe_max_size is not None:
                            offset = TestSequenceBytesOffset(offsets, safe_min_size, safe_max_size)

                        if offset is None:
                            offset = TestSequenceBytesOffset(offsets, -1, -1)

    if offset is not None:
        suggested_hardcore_sequence_bytes_offset = offset

    if sequence_bytes_offset is not None:
        first_segment_to_segment_before_memhole_matches += 1

        if suggested_sequence_bytes_offset is not None:
            if suggested_sequence_bytes_offset == sequence_bytes_offset:
                suggested_sequence_bytes_offset_matches += 1
            else:
                suggested_sequence_bytes_offset_mismatches += 1
        else:
            suggested_sequence_bytes_offset_mismatches += 1

        if suggested_hardcore_sequence_bytes_offset is not None:
            if suggested_hardcore_sequence_bytes_offset == sequence_bytes_offset:
                suggested_hardcore_sequence_bytes_offset_matches += 1
            else:
                suggested_hardcore_sequence_bytes_offset_mismatches += 1
        else:
            suggested_hardcore_sequence_bytes_offset_mismatches += 1
    else:
        # if they're None it isn't a match, because a match must mean that both of them aren't None and they're equal

        if suggested_sequence_bytes_offset is not None:
            suggested_sequence_bytes_offset_mismatches += 1

        if suggested_hardcore_sequence_bytes_offset is not None:
            suggested_hardcore_sequence_bytes_offset_mismatches += 1

    overwrite_sequence_bytes_offset = (sequence_bytes_offset is None or ((sequence_bytes_offset_use_options & int("0001", 2)) > 0))

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
            prioritize_suggested_hardcore_sequence_bytes_offset_over_suggested_sequence_bytes_offset = (
                (sequence_bytes_offset_use_options & int("1000", 2)) > 0
            )

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

    result = (
        sequence_bytes_offset is not None
        and
        (
            suggested_hardcore_sequence_bytes_offset_test is False
            or (  # means the test is True, in that case we return True only if the suggested hardcore sequence bytes offset matches the sequence bytes offset
                suggested_hardcore_sequence_bytes_offset is not None
                and suggested_hardcore_sequence_bytes_offset == sequence_bytes_offset
            )
        )
    )

    return result


def check_cs():  # returns -1 in case of failure, 0 in case of not finding a match, and 1 in case of success
    result = None

    # Global Variables

    # global dry_run
    global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    global successes
    global success_text

    # global failures
    global failure_text

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    global current_head
    # global next_head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    global cmd_fixed_splitted
    global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    global cmd_fixed_splitted_cell
    global cmd_fixed_splitted_cell_length
    global cmd_fixed_splitted_cell_index

    global position

    global cs_structures
    global cs_address
    global cs_text
    global cs_text_length

    # global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

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

    if cmd_fixed_splitted_cell_length >= cs_text_length + 2:  # need at least 1 number and 1 'h' (mentioning an hexa number)
        if cmd_fixed_splitted_cell[:cs_text_length] == cs_text:
            for cmd_fixed_splitted_cell_index in range(cs_text_length, cmd_fixed_splitted_cell_length):
                if cmd_fixed_splitted_cell[cmd_fixed_splitted_cell_index] in string.hexdigits:
                    continue
                elif cmd_fixed_splitted_cell[cmd_fixed_splitted_cell_index] == 'h':
                    if cmd_fixed_splitted_cell_index > cs_text_length:
                        if cmd_fixed_splitted_cell_index < cmd_fixed_splitted_cell_length - 1:
                            failure_text = "can't parse cs (can't handle additions/substractions or any math functions)"

                            error_found = True
                        else:
                            method_found = True

                    break
                else:
                    break

            if method_found is True:
                method_found = False

                CreateSequence(current_head, None)  # no need to check for the result, assuming it is True

                if sequence_bytes_amount < min_bytes_estimated_amount:
                    failure_text = (
                        "the sequence bytes amount"
                        + ' ' + str(sequence_bytes_amount)
                        + ' ' + "is smaller than the min bytes estimated amount"
                        + ' ' + str(min_bytes_estimated_amount)
                    )

                    error_found = True
                else:
                    cs_address = int(cmd_fixed_splitted_cell[cs_text_length:cmd_fixed_splitted_cell_length - 1], 16)

                    if cs_address >= safe_min_bytes_size and cs_address <= safe_max_bytes_size:
                        if CheckSequenceBytesOffset(cs_structures) is False:
                            failure_text = "couldn't find a suitable sequence bytes offset"

                            if (
                                position != cmd_fixed_splitted_amount
                                and position + 1 != cmd_fixed_splitted_amount
                                and position + 2 != cmd_fixed_splitted_amount
                            ):
                                failure_text += ',' + ' ' + "not supporting a command that cs isn't in a range between last cell to 2 cells before it"

                            if sequence_bytes_offset is not None:
                                failure_text += '\t' + "offset:" + ' ' + str(sequence_bytes_offset)

                            if suggested_sequence_bytes_offset is not None:
                                failure_text += '\t' + "suggested offset:" + ' ' + str(suggested_sequence_bytes_offset)

                            if suggested_hardcore_sequence_bytes_offset is not None:
                                failure_text += '\t' + "suggested hardcore offset:" + ' ' + str(suggested_hardcore_sequence_bytes_offset)

                            error_found = True
                        else:
                            if verbose is True:
                                SequenceBytesText = CheckSequenceBytesText(True)

                            PatchSequenceBytes()

                            success_text = (
                                "Patched cs bytes"
                                + '\t' + "address:" + ' ' + CheckHexText(fixed_bytes_address, AddressesLength, True)
                                + '\t' + "command:" + ' ' + '\t'.join(cmd_fixed_splitted)
                                + '\t' + "position:" + ' ' + str(position) + ' ' + "out of:" + ' ' + str(cmd_fixed_splitted_amount)
                                + '\t' + "offset:" + ' ' + str(sequence_bytes_offset)
                                + '\t' + "cs address:" + ' ' + CheckHexText(cs_address, AddressesLength, True)
                                + (('\t' + "sequence bytes:" + ' ' + SequenceBytesText) if SequenceBytesText is not None else "")
                                + '\t' + "original bytes:" + ' ' + CheckHexText(original_bytes_size, original_bytes_amount * 2, True)
                                + '\t' + "patched bytes:" + ' ' + CheckHexText(fixed_bytes_size, fixed_bytes_amount * 2, True)
                            )

                            if verbose is True:
                                print(success_text)

                            successes += 1

                            method_found = True

                    cs_address = None

    if method_found is True:
        result = 1
    elif error_found is True:
        result = -1
    else:
        result = 0

    return result


def check_static_TP():  # returns -1 in case of failure, 0 in case of not finding a match, and 1 in case of success
    result = None

    # Global Variables

    # global dry_run
    global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    global successes
    global success_text

    # global failures
    global failure_text

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    global current_head
    # global next_head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    global cmd_fixed_splitted
    global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    global cmd_fixed_splitted_cell
    global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    global position

    # global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    global static_TP_structures
    global static_TP_text
    global static_TP_text_length

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    # global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    # global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

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
                failure_text = "can't parse static_TP (can't handle additions/substractions or any math functions)"

                error_found = True
            else:
                CreateSequence(current_head, None)  # no need to check for the result, assuming it is True

                if sequence_bytes_amount < min_bytes_estimated_amount:
                    failure_text = (
                        "the sequence bytes amount"
                        + ' ' + str(sequence_bytes_amount)
                        + ' ' + "is smaller than the min bytes estimated amount"
                        + ' ' + str(min_bytes_estimated_amount)
                    )

                    error_found = True
                else:
                    if CheckSequenceBytesOffset(static_TP_structures) is False:
                        failure_text = "couldn't find a suitable sequence bytes offset"

                        if (
                            position != cmd_fixed_splitted_amount
                        ):
                            failure_text += ',' + ' ' + "not supporting a command that static_TP isn't in the last cell"

                        if sequence_bytes_offset is not None:
                            failure_text += '\t' + "offset:" + ' ' + str(sequence_bytes_offset)

                        if suggested_sequence_bytes_offset is not None:
                            failure_text += '\t' + "suggested offset:" + ' ' + str(suggested_sequence_bytes_offset)

                        if suggested_hardcore_sequence_bytes_offset is not None:
                            failure_text += '\t' + "suggested hardcore offset:" + ' ' + str(suggested_hardcore_sequence_bytes_offset)

                        error_found = True
                    else:
                        if verbose is True:
                            SequenceBytesText = CheckSequenceBytesText(True)

                        PatchSequenceBytes()

                        success_text = (
                            "Patched static_TP bytes"
                            + '\t' + "address:" + ' ' + CheckHexText(fixed_bytes_address, AddressesLength, True)
                            + '\t' + "command:" + ' ' + '\t'.join(cmd_fixed_splitted)
                            + '\t' + "position:" + ' ' + str(position) + ' ' + "out of:" + ' ' + str(cmd_fixed_splitted_amount)
                            + '\t' + "offset:" + ' ' + str(sequence_bytes_offset)
                            + (('\t' + "sequence bytes:" + ' ' + SequenceBytesText) if SequenceBytesText is not None else "")
                            + '\t' + "original bytes:" + ' ' + CheckHexText(original_bytes_size, original_bytes_amount * 2, True)
                            + '\t' + "patched bytes:" + ' ' + CheckHexText(fixed_bytes_size, fixed_bytes_amount * 2, True)
                        )

                        if verbose is True:
                            print(success_text)

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
    # global verbose
    # global sound

    global FirstSegment_VirtualAddress

    global SegmentBeforeMemHole_VirtualAddress

    # global SegmentAfterMemHole_Unmapped_VirtualAddress
    # global SegmentAfterMemHole_Mapped_VirtualAddress
    # global SegmentAfterMemHole_MemorySize

    # global sequence_bytes_offset_use_options

    # global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    global failures
    global failure_text

    # global patched_bytes

    # global first_segment_to_segment_before_memhole_matches

    global heads
    global heads_amount
    global heads_index
    global previous_head
    global current_head
    global next_head

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

    global position

    # global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    # global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

    # global sequence_bytes
    # global sequence_bytes_address
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

    check_cs_result = None
    check_static_TP_result = None

    SequenceBytesText = None

    error_message = None

    method_found = False
    error_found = False

    # Start

    #
    # #
    # # # going through all of the functions/commands in all of the addresses from the first segment virtual address
    # # # to the segment after the mem hole mapped virtual address + its file size (not including the last one since it's an address of the next segment)
    # #
    #

    # going through all of the heads from first segment virtual address
    # to the segment before mem hole virtual address (not including the last one since it's an address of the next segment)

    print("")
    print("parsing addresses between the first segment to the segment before the memory hole")

    heads = CheckHeads(FirstSegment_VirtualAddress, SegmentBeforeMemHole_VirtualAddress - 1)
    heads_amount = len(heads)

    # heads_amount = 0

    for heads_index in range(0, heads_amount):
        previous_head = None
        current_head = None
        next_head = None

        if heads_index > 0:
            previous_head = heads[heads_index - 1]

        current_head = heads[heads_index]

        if heads_index < heads_amount - 1:
            next_head = heads[heads_index + 1]

        # print(CheckHexText(previous_head, AddressesLength, True))
        # print(CheckHexText(current_head, AddressesLength, True))
        # print(CheckHexText(next_head, AddressesLength, True))

        cmd = CheckCommand(current_head)

        if cmd is not None:
            cmd_length = len(cmd)

            if cmd_length > 0:
                # print(cmd)

                failure_text = None

                cmd_fixed = None
                cmd_fixed_length = None
                cmd_fixed_splitted = None
                cmd_fixed_splitted_amount = None
                cmd_fixed_splitted_index = None
                cmd_fixed_splitted_cell = None
                cmd_fixed_splitted_cell_length = None
                cmd_fixed_splitted_cell_index = None

                position = None

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

                                        position = cmd_fixed_splitted_index + 1

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

                    if failure_text is not None:
                        error_message.append("reason:" + ' ' + failure_text)

                    error_message.append("address:" + ' ' + CheckHexText(current_head, AddressesLength, True))

                    if cmd_fixed_splitted is not None:
                        error_message.append("command:" + ' ' + '\t'.join(cmd_fixed_splitted))

                    if position is not None:
                        error_message.append("position:" + ' ' + str(position) + ' ' + "out of:" + ' ' + str(cmd_fixed_splitted_amount))

                    if CreateSequence(current_head, None) is True:
                        SequenceBytesText = CheckSequenceBytesText(True)

                        if SequenceBytesText is not None:
                            error_message.append("sequence bytes upwards:" + ' ' + SequenceBytesText)

                        SequenceBytesText = CheckSequenceBytesText(False)

                        if SequenceBytesText is not None:
                            error_message.append("sequence bytes downwards:" + ' ' + SequenceBytesText)

                    print('\t'.join(error_message))

                    failures += 1

    print("")
    print("finished parsing addresses between first segment to the segment before the memory hole")

    # going through all of the addresses from segment before mem hole virtual address
    # to the segment after the mem hole mapped virtual address + its file size (not including the last one since it's an address of the next segment)

    # print("")
    # print("parsing addresses between the segment before the memory hole to the segment after the memory hole and its file size")

    # print("")
    # print("finished parsing addresses between the segment before the memory hole to the segment after the memory hole and its file size")


def main():
    # Global Variables

    global dry_run
    global verbose
    global sound

    global FirstSegment_VirtualAddress

    global SegmentBeforeMemHole_VirtualAddress

    global SegmentAfterMemHole_Unmapped_VirtualAddress
    global SegmentAfterMemHole_Mapped_VirtualAddress
    global SegmentAfterMemHole_MemorySize

    global sequence_bytes_offset_use_options

    global suggested_hardcore_sequence_bytes_offset_test

    global BytesLength
    global SizesLength
    global AddressesLength

    global successes
    # global success_text

    global failures
    # global failure_text

    global patched_bytes

    global first_segment_to_segment_before_memhole_matches

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

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

    # global position

    # global cs_structures
    # global cs_address
    # global cs_text
    # global cs_text_length

    # global static_TP_structures
    # global static_TP_text
    # global static_TP_text_length

    # global mem_hole_size

    # global min_bytes_size
    # global min_bytes_amount
    # global min_bytes_estimated_amount

    # global max_bytes_size
    # global max_bytes_amount
    # global max_bytes_estimated_amount

    # global safe_min_bytes_size
    # global safe_min_bytes_amount
    # global safe_min_bytes_estimated_amount

    # global safe_max_bytes_size
    # global safe_max_bytes_amount
    # global safe_max_bytes_estimated_amount

    # global sequence_bytes
    # global sequence_bytes_address
    # global sequence_bytes_original_amount
    # global sequence_bytes_amount
    # global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    # global suggested_sequence_bytes_offset
    global suggested_sequence_bytes_offset_matches
    global suggested_sequence_bytes_offset_mismatches

    # global suggested_hardcore_sequence_bytes_offset
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

    start_time = None
    end_time = None

    elapsedTime = None

    elapsedMinutes = None
    elapsedSeconds = None

    # Start

    WaitForInitialAutoanalysis()

    start_time = datetime.now().time().strftime('%H:%M:%S')

    print("")
    print("User Input:")
    print(
        "Dry Run:" + ' ' + ("True" if dry_run is True else "False") + "\n"
        + "Verbose:" + ' ' + ("True" if verbose is True else "False") + "\n"
        + "First Segment Virtual Address:" + ' ' + CheckHexText(FirstSegment_VirtualAddress, AddressesLength, True) + "\n"
        + "Segment Before Memory Hole Virtual Address:" + ' ' + CheckHexText(SegmentBeforeMemHole_VirtualAddress, AddressesLength, True) + "\n"
        + "Segment After Memory Hole Unmapped Virtual Address:" + ' ' + CheckHexText(SegmentAfterMemHole_Unmapped_VirtualAddress, AddressesLength, True) + "\n"
        + "Segment After Memory Hole Mapped Virtual Address:" + ' ' + CheckHexText(SegmentAfterMemHole_Mapped_VirtualAddress, AddressesLength, True) + "\n"
        + "Segment After Memory Hole Memory Size:" + ' ' + CheckHexText(SegmentAfterMemHole_MemorySize, SizesLength, True)
    )

    print("")
    print("Program Input:")
    print(
        "Sequence Bytes Offset Use Options:" + ' ' + CheckBinText(sequence_bytes_offset_use_options, 4, False) + "\n"
        "Suggested Hardcore Sequence Bytes Offset Test:" + ' ' + ("True" if suggested_hardcore_sequence_bytes_offset_test is True else "False")
    )

    CreateStructures()
    CombineStructures()

    # for structure in static_TP_structures:
    #     print(str(structure))

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

    # print("")
    # print("matches between the segment before the memory hole to the segment after the memory hole and its file size:")

    print("")
    print("elapsed time:" + ' ' + str(elapsedMinutes).zfill(2) + ':' + str(elapsedSeconds).zfill(2))

    if sound is True:
        CompletionSound()

    print("")
    print("done")


main()
