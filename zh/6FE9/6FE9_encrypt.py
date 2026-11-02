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
        raise ValueError("ICCID 必须正好是 20 个字符 (例如: 8981300020123456780F)")
        
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
        print(f"用法: python {Path(sys.argv[0]).name} <edited_decrypted.bin> <ICCID>")
        print(f"示例: python {Path(sys.argv[0]).name} edited_decrypted.bin 8981300020123456780F")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    iccid_str = sys.argv[2].replace(" ", "").strip()

    if not input_path.is_file():
        print(f"[-] 错误: 找不到文件 {input_path}")
        sys.exit(1)

    # 1. 解析 ICCID 并生成对应的 XOR 密钥
    # 1. Parse ICCID and generate corresponding XOR key
    try:
        key = derive_key_from_iccid(iccid_str)
    except Exception as e:
        print(f"[-] ICCID 格式或密钥计算错误: {e}")
        sys.exit(1)
        
    key_hex = " ".join(f"{b:02X}" for b in key)
    print(f"[*] 解析 ICCID: {iccid_str}")
    print(f"[*] 成功派生 XOR 密钥: {key_hex}")

    # 读取解密状态的 bin 文件
    # Read decrypted bin file
    data = bytearray(input_path.read_bytes())

    # 检查并修复文件大小 (补齐至 0x0C00)
    # Check and fix file size (pad up to 0x0C00)
    if len(data) < 0x0C00:
        print(f"[*] 文件大小不足 (当前 {len(data)} bytes)，正在自动补齐至 0x0C00...")
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
    
    print(f"[*] 正在基于【解密明文】计算校验和...")
    print(f"    -> Main区 (0x100-0x5FF) 明文 SUM = 0x{main_sum:X}")
    print(f"    -> Extra区 (0x700-0x71F) 原文 SUM = 0x{extra_sum:X}")
    print(f"    -> Initial 常数 = 0x{INITIAL:02X}")
    print(f"[!] 最终 Checksum (0x0BF8) = 0x{checksum:02X}")

    # 写入校验码
    # Write checksum
    data[0x0BF8] = checksum

    # 3. 加密数据区
    # 3. Encrypt data area
    print(f"[*] 正在对 0x100-0x5FF 区域进行 XOR 加密...")
    for i in range(0x100, 0x600):
        data[i] ^= key[(i + 2) % 10]

    # 4. 自动命名并导出结果
    # 4. Automatically name and export results
    out_name = input_path.name.replace("_decrypted", "_encrypted")
    if out_name == input_path.name:
        out_name = input_path.stem + "_encrypted" + input_path.suffix
        
    out_path = input_path.parent / out_name
    out_path.write_bytes(data)

    print(f"\n[+] 加密完成！")
    print(f"[+] 保存路径: {out_path}")

if __name__ == "__main__":
    main()