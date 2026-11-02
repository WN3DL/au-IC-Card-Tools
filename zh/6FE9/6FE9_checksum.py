#!/usr/bin/env python3
import sys
from pathlib import Path

# Main data: 0x100 ~ 0x5FF, 1280 bytes
MAIN_OFFSET = 0x100
MAIN_LENGTH = 0x500

# Additional data: 0x700 ~ 0x71F, 32 bytes
EXTRA_OFFSET = 0x700
EXTRA_LENGTH = 0x20

# Fixed initial value
INITIAL = 0x28


def calculate_checksum(filename):
    path = Path(filename)

    if not path.is_file():
        raise FileNotFoundError(f"文件不存在: {path}")

    data = path.read_bytes()

    main_end = MAIN_OFFSET + MAIN_LENGTH
    extra_end = EXTRA_OFFSET + EXTRA_LENGTH

    if len(data) < extra_end:
        raise ValueError(
            f"文件太小：{len(data)} bytes，"
            f"至少需要 0x{extra_end:X} bytes ({extra_end} bytes)"
        )

    # 0x100 ~ 0x5FF
    main_data = data[MAIN_OFFSET:main_end]

    # 0x700 ~ 0x71F
    extra_data = data[EXTRA_OFFSET:extra_end]

    main_sum = sum(main_data)
    extra_sum = sum(extra_data)

    checksum = (main_sum + extra_sum + INITIAL) & 0xFF

    return main_data, extra_data, main_sum, extra_sum, checksum


def main():
    if len(sys.argv) != 2:
        print(f"用法: {Path(sys.argv[0]).name} <file.bin>")
        sys.exit(1)

    try:
        main_data, extra_data, main_sum, extra_sum, checksum = \
            calculate_checksum(sys.argv[1])

        print(f"Main   0x100-0x5FF : {len(main_data):4d} bytes, "
              f"SUM = 0x{main_sum:X}, SUM8 = 0x{main_sum & 0xFF:02X}")

        print(f"Extra  0x700-0x71F : {len(extra_data):4d} bytes, "
              f"SUM = 0x{extra_sum:X}, SUM8 = 0x{extra_sum & 0xFF:02X}")

        print(f"Initial             : 0x{INITIAL:02X}")

        print(
            f"Checksum            : "
            f"(0x{main_sum:X} + 0x{extra_sum:X} + 0x{INITIAL:02X}) & 0xFF"
        )
        print(f"                    = 0x{checksum:02X}")

    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()