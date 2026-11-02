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

def generate_c_array(name, data_chunk):
    """
    将数据块格式化为 C 语言数组格式 (16字节一行)
    Format data block into C language array format (16 bytes per line)
    """
    length = len(data_chunk)
    lines = []
    lines.append(f"const unsigned char code {name}[{length}] = {{")
    
    for i in range(0, length, 16):
        part = data_chunk[i:i+16]
        hex_str = ", ".join(f"0x{b:02X}" for b in part)
        if i + 16 < length:
            hex_str += ","
        lines.append(hex_str)
        
    lines.append("};\n")
    return "\n".join(lines)

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

    # 4. 生成导出的文件名
    # 4. Generate exported file names
    out_name_bin = input_path.name.replace("_decrypted", "_encrypted")
    if out_name_bin == input_path.name:
        out_name_bin = input_path.stem + "_encrypted.bin"
    out_path_bin = input_path.parent / out_name_bin

    out_name_txt = out_name_bin.replace(".bin", ".txt")
    out_path_txt = input_path.parent / out_name_txt

    # 5. 保存 .bin 镜像文件
    # 5. Save .bin image file
    out_path_bin.write_bytes(data)

    # 6. 生成并保存 C 数组 .txt 格式文件
    # 6. Generate and save C array .txt format file
    print(f"[*] 正在生成 C 语言数组源码格式文件...")
    c_arrays = []
    
    c_arrays.append(generate_c_array("file_6FE9_0100", data[0x0100:0x0200]))
    c_arrays.append(generate_c_array("file_6FE9_0200", data[0x0200:0x0300]))
    c_arrays.append(generate_c_array("file_6FE9_0300", data[0x0300:0x0400]))
    c_arrays.append(generate_c_array("file_6FE9_0400", data[0x0400:0x0500]))
    c_arrays.append(generate_c_array("file_6FE9_0500", data[0x0500:0x0600]))
    c_arrays.append(generate_c_array("file_6FE9_0700_32B", data[0x0700:0x0720]))
    c_arrays.append(generate_c_array("file_6FE9_0BF8", data[0x0BF8:0x0BF9]))

    out_path_txt.write_text("\n".join(c_arrays), encoding="utf-8")

    print(f"\n[+] 加密完成！")
    print(f"    -> 镜像文件: {out_path_bin}")
    print(f"    -> 源码文件: {out_path_txt}")

if __name__ == "__main__":
    main()