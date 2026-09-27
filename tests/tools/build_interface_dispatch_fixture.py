#!/usr/bin/env python3
import struct
import sys
from pathlib import Path


HELPER = 0x100
OBJECT_NEW = 0x200
OBJECT_NEW_THUNK = 0x210
OBJECT_NEW_ANCHOR = 0x220
TARGET = 0x240
METHOD = 0x300
CANONICAL_CALLER = 0x400
FACTORY_CALLER = 0x440
DELEGATE_CALLER = 0x480
DELEGATE_MISMATCH_CALLER = 0x4A0
DELEGATE_TAIL_CALLER = 0x4C0
SHARED_GENERIC_CALLER = 0x540
SHARED_GENERIC_BODY = 0x560
SHARED_GENERIC_METHOD_INFO = 0x580
SHARED_GENERIC_CALLER_ONE_ARG = 0x5A0
SHARED_GENERIC_METHOD_INFO_ONE_ARG = 0x5C0
SHARED_GENERIC_CALLER_THREE_ARGS = 0x600
SHARED_GENERIC_METHOD_INFO_THREE_ARGS = 0x620
NATIVE_CALL = 0x180
CONDITION_TARGET = 0x190
RECEIVER_TYPE = 0x500
INTERFACE_TYPE = 0x508
RECEIVER_TYPE_GOT = 0x520
INTERFACE_TYPE_GOT = 0x528
IMAGE_BASE = 0x1000


def branch(opcode, address, target):
    return opcode | (((target - address) >> 2) & 0x03FF_FFFF)


def conditional(address, target, register=0):
    immediate = ((target - address) >> 2) & 0x7FFFF
    return 0xB500_0000 | (immediate << 5) | register


def move(destination, source, wide=True):
    return (0xAA00_03E0 if wide else 0x2A00_03E0) | (source << 16) | destination


def adr(address, target, register):
    displacement = target - address
    immediate_low = displacement & 3
    immediate_high = (displacement >> 2) & 0x7FFFF
    return 0x1000_0000 | (immediate_low << 29) | (immediate_high << 5) | register


def load(destination, base):
    return 0xF940_0000 | (base << 5) | destination


def load_at(destination, base, offset):
    if offset % 8 != 0 or offset < 0 or offset >= 0x8000:
        raise ValueError("invalid 64-bit load offset")
    return 0xF940_0000 | ((offset // 8) << 10) | (base << 5) | destination


def write_words(data, offset, words):
    for index, word in enumerate(words):
        struct.pack_into("<I", data, offset + index * 4, word)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: build_interface_dispatch_fixture.py OUTPUT")

    data = bytearray(0x700)
    for offset in range(0, len(data), 4):
        struct.pack_into("<I", data, offset, 0xD503_201F)

    helper_words = [
        0xA9BD_5FFE,
        move(22, 0),
        move(20, 1),
        move(19, 2, False),
        branch(0x9400_0000, HELPER + 0x10, NATIVE_CALL),
        conditional(HELPER + 0x14, CONDITION_TARGET),
        0xD503_201F,
        0xD503_201F,
        0xD503_201F,
        0xD503_201F,
        0xD503_201F,
        0xD503_201F,
        0xD65F_03C0,
    ]
    write_words(data, HELPER, helper_words)
    write_words(data, NATIVE_CALL, [0xD65F_03C0])
    write_words(data, CONDITION_TARGET, [0xD65F_03C0])
    write_words(data, OBJECT_NEW, [branch(0x1400_0000, OBJECT_NEW, OBJECT_NEW_THUNK)])
    write_words(data, OBJECT_NEW_THUNK, [
        branch(0x1400_0000, OBJECT_NEW_THUNK, OBJECT_NEW_ANCHOR)
    ])
    write_words(data, OBJECT_NEW_ANCHOR, [0xD65F_03C0])
    write_words(data, TARGET, [0xD65F_03C0])

    fast_path = METHOD + 0x2C
    merge = METHOD + 0x38
    method_words = [
        adr(METHOD, RECEIVER_TYPE_GOT, 10),
        load(0, 10),
        branch(0x9400_0000, METHOD + 0x08, OBJECT_NEW),
        move(19, 0),
        adr(METHOD + 0x10, INTERFACE_TYPE_GOT, 10),
        load(1, 10),
        conditional(METHOD + 0x18, fast_path, 11),
        move(0, 19),
        0x2A1F_03E2,
        branch(0x9400_0000, METHOD + 0x24, HELPER),
        branch(0x1400_0000, METHOD + 0x28, merge),
        0xB980_0149,
        0x8B09_1108,
        0x9104_E100,
        0xA940_0408,
        move(0, 19),
        0xD63F_0100,
        0xD63F_0120,
        0xD63F_0180,
        0xD65F_03C0,
    ]
    write_words(data, METHOD, method_words)
    write_words(data, CANONICAL_CALLER, [
        branch(0x9400_0000, CANONICAL_CALLER, OBJECT_NEW_ANCHOR),
        branch(0x9400_0000, CANONICAL_CALLER + 0x04, HELPER),
        0xD65F_03C0,
    ])
    write_words(data, FACTORY_CALLER, [
        branch(0x9400_0000, FACTORY_CALLER, HELPER),
        0xD65F_03C0,
    ])
    write_words(data, DELEGATE_CALLER, [
        move(8, 0),
        load_at(10, 8, 24),
        load_at(0, 8, 64),
        0x5280_00E1,
        load_at(2, 8, 40),
        0xD63F_0140,
        0xD65F_03C0,
    ])
    write_words(data, DELEGATE_MISMATCH_CALLER, [
        move(8, 0),
        move(9, 1),
        load_at(10, 8, 24),
        load_at(0, 8, 64),
        0x5280_00E1,
        load_at(2, 9, 40),
        0xD63F_0140,
        0xD65F_03C0,
    ])
    write_words(data, DELEGATE_TAIL_CALLER, [
        move(8, 0),
        load_at(10, 8, 24),
        load_at(0, 8, 64),
        0x5280_00E1,
        load_at(2, 8, 40),
        0xD61F_0140,
    ])
    write_words(data, SHARED_GENERIC_CALLER, [
        adr(SHARED_GENERIC_CALLER, SHARED_GENERIC_METHOD_INFO, 8),
        load(3, 8),
        0x9100_23E2,
        0x5280_00E1,
        branch(0x9400_0000, SHARED_GENERIC_CALLER + 0x10, SHARED_GENERIC_BODY),
        0xD65F_03C0,
    ])
    write_words(data, SHARED_GENERIC_CALLER_ONE_ARG, [
        adr(SHARED_GENERIC_CALLER_ONE_ARG, SHARED_GENERIC_METHOD_INFO_ONE_ARG, 8),
        load(2, 8),
        0x9100_23E1,
        branch(0x9400_0000, SHARED_GENERIC_CALLER_ONE_ARG + 0x0C, SHARED_GENERIC_BODY),
        0xD65F_03C0,
    ])
    write_words(data, SHARED_GENERIC_CALLER_THREE_ARGS, [
        adr(SHARED_GENERIC_CALLER_THREE_ARGS,
            SHARED_GENERIC_METHOD_INFO_THREE_ARGS, 8),
        load(4, 8),
        0x9100_63E3,
        branch(0x9400_0000, SHARED_GENERIC_CALLER_THREE_ARGS + 0x0C,
               SHARED_GENERIC_BODY),
        0xD65F_03C0,
    ])
    write_words(data, SHARED_GENERIC_BODY, [0xD65F_03C0])
    struct.pack_into("<Q", data, SHARED_GENERIC_METHOD_INFO, 0x2700)
    struct.pack_into("<Q", data, SHARED_GENERIC_METHOD_INFO_ONE_ARG, 0x2800)
    struct.pack_into("<Q", data, SHARED_GENERIC_METHOD_INFO_THREE_ARGS, 0x2900)
    struct.pack_into("<Q", data, RECEIVER_TYPE, 0x2500)
    struct.pack_into("<Q", data, INTERFACE_TYPE, 0x2600)
    struct.pack_into("<Q", data, RECEIVER_TYPE_GOT, IMAGE_BASE + RECEIVER_TYPE)
    struct.pack_into("<Q", data, INTERFACE_TYPE_GOT, IMAGE_BASE + INTERFACE_TYPE)
    Path(sys.argv[1]).write_bytes(data)


if __name__ == "__main__":
    main()
