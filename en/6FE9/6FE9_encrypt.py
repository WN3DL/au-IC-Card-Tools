#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from pathlib import Path

def nibble_swap(b):
    """
    半字节交换 (例如: 0x57 -> 0x75)
    Nibble swap (e.g.: 0x57 -> 0x75)
    """
    return ((b & 0x0F) << 4) | ((b & 0xF0) >> 4)

def bit_reverse(b):
    """
    8位二进制反转 (例如: 0x75 -> 0xAE)
    8-bit binary reversal (e.g.: 0x75 -> 0xAE)
    """
    return int('{:08b}'.format(b)[::-1], 2)

def derive_key_from_iccid(iccid_hex):
    """
    通过算法从 ICCID 派生 10 字节 XOR 密钥
    Derive 10-byte XOR key from ICCID via algorithm
    """
    if len(iccid_hex) != 20:
        raise ValueError("ICCID must be exactly 20 characters (e.g.: 8981300020123456780F)")
        
    P = bytes.fromhex(iccid_hex)
    key = bytearray(10)
    
    key[0] = nibble_swap(P[2])
    key[1] = nibble_swap(P[3])
    key[2] = bit_reverse(nibble_swap(P[6]))
    key[3] = bit_reverse(nibble_swap(P[5]))
    key[4] = bit_reverse(nibble_swap(P[4]))
    key[5] = bit_reverse(nibble_swap(P[7]))
    key[6] = bit_reverse(nibble_swap(P[2]))
    key[7] = bit_reverse(nibble_swap(P[9]))
    key[8] = nibble_swap(P[0])
    key[9] = nibble_swap(P[1])
    
    return key

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {Path(sys.argv[0]).name} <edited_decrypted.bin> <ICCID>")
        print(f"Example: python {Path(sys.argv[0]).name} edited_decrypted.bin 8981300020123456780F")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    iccid_str = sys.argv[2].replace(" ", "").strip()

    if not input_path.is_file():
        print(f"[-] Error: File {input_path} not found")
        sys.exit(1)

    # 1. 解析 ICCID 并生成对应的 XOR 密钥
    # 1. Parse ICCID and generate corresponding XOR key
    try:
        key = derive_key_from_iccid(iccid_str)
    except Exception as e:
        print(f"[-] ICCID format or key calculation error: {e}")
        sys.exit(1)
        
    key_hex = " ".join(f"{b:02X}" for b in key)
    print(f"[*] Parsed ICCID: {iccid_str}")
    print(f"[*] Successfully derived XOR key: {key_hex}")

    # 读取解密状态的 bin 文件
    # Read decrypted bin file
    data = bytearray(input_path.read_bytes())

    # 检查并修复文件大小 (补齐至 0x0C00)
    # Check and fix file size (pad up to 0x0C00)
    if len(data) < 0x0C00:
        print(f"[*] Insufficient file size (current {len(data)} bytes), padding to 0x0C00...")
        data.extend(bytearray(0x0C00 - len(data)))

    # 2. 在【明文状态】下计算 Checksum
    # 2. Calculate Checksum under [plaintext state]
    MAIN_OFFSET = 0x100
    MAIN_LENGTH = 0x500
    EXTRA_OFFSET = 0x700
    EXTRA_LENGTH = 0x20
    INITIAL = 0x28

    main_sum = sum(data[MAIN_OFFSET : MAIN_OFFSET + MAIN_LENGTH])
    extra_sum = sum(data[EXTRA_OFFSET : EXTRA_OFFSET + EXTRA_LENGTH])
    
    checksum = (main_sum + extra_sum + INITIAL) & 0xFF
    
    print(f"[*] Calculating checksum based on [decrypted plaintext]...")
    print(f"    -> Main area (0x100-0x5FF) plaintext SUM = 0x{main_sum:X}")
    print(f"    -> Extra area (0x700-0x71F) raw SUM = 0x{extra_sum:X}")
    print(f"    -> Initial constant = 0x{INITIAL:02X}")
    print(f"[!] Final Checksum (0x0BF8) = 0x{checksum:02X}")

    # 写入校验码
    # Write checksum
    data[0x0BF8] = checksum

    # 3. 加密数据区
    # 3. Encrypt data area
    print(f"[*] XOR encryption in progress for 0x100-0x5FF area...")
    for i in range(0x100, 0x600):
        data[i] ^= key[(i + 2) % 10]

    # 4. 自动命名并导出结果
    # 4. Automatically name and export results
    out_name = input_path.name.replace("_decrypted", "_encrypted")
    if out_name == input_path.name:
        out_name = input_path.stem + "_encrypted" + input_path.suffix
        
    out_path = input_path.parent / out_name
    out_path.write_bytes(data)

    print(f"\n[+] Encryption complete!")
    print(f"[+] Saved to: {out_path}")

if __name__ == "__main__":
    main()