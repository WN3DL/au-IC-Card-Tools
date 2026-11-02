#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import re
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

def get_string(data, start_offset, end_offset):
    """
    读取指定区间的 ASCII 字符串，遇到 0x00/0xFF 或到达 end_offset 截断
    Read ASCII string in specified range, truncated at 0x00/0xFF or end_offset
    """
    if start_offset >= len(data): return ""
    chunk = data[start_offset:min(end_offset, len(data))]
    res = bytearray()
    for b in chunk:
        if b == 0x00 or b == 0xFF:
            break
        res.append(b)
    return res.decode('ascii', errors='ignore').strip()

def get_ip_str(data, offset):
    """
    提取单个 IPv4 地址，无效则返回 None
    Extract a single IPv4 address, return None if invalid
    """
    if offset + 4 > len(data): return None
    chunk = data[offset:offset+4]
    # 如果遇到空数据或者未分配数据，不作为 IP 返回
    # If empty or unallocated data is encountered, do not return as IP
    if chunk == b'\xff\xff\xff\xff' or chunk == b'\x00\x00\x00\x00':
        return None
    return f"{chunk[0]}.{chunk[1]}.{chunk[2]}.{chunk[3]}"

def get_hex(data, offset, length):
    """
    读取指定长度的十六进制字符串
    Read a hexadecimal string of specified length
    """
    if offset >= len(data): return ""
    chunk = data[offset:min(offset+length, len(data))]
    return " ".join(f"{b:02X}" for b in chunk)

def main():
    if len(sys.argv) < 2:
        print(f"用法: python {Path(sys.argv[0]).name} <input.bin> [ICCID]")
        print(f"示例 1 (自动提取密钥): python {Path(sys.argv[0]).name} 8981300020123456780F_6FE9.bin")
        print(f"示例 2 (ICCID派生密钥): python {Path(sys.argv[0]).name} sample.bin 8981300020123456780F")
        sys.exit(1)

    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"[-] 错误: 找不到文件 '{input_file}'。")
        sys.exit(1)

    # 读取 .bin 原始二进制数据
    # Read raw binary data from .bin
    with open(input_file, 'rb') as f:
        raw_data = bytearray(f.read())

    if len(raw_data) == 0:
        print("[-] 错误: 输入的 .bin 文件为空！")
        sys.exit(1)

    # 完整 6FE9 文件大小应为 0xC00 (3072) 字节，不足则自动补齐
    # Complete 6FE9 file size should be 0xC00 (3072) bytes, pad if insufficient
    if len(raw_data) < 0xC00:
        print(f"[*] 文件大小不足 (当前 {len(raw_data)} bytes)，正在自动补齐至 0x0C00...")
        raw_data.extend(bytearray(0xC00 - len(raw_data)))

    # 获取/派生解密密钥
    # Obtain/derive decryption key
    if len(sys.argv) >= 3:
        iccid_str = sys.argv[2].replace(" ", "").strip()
        try:
            key = derive_key_from_iccid(iccid_str)
            print(f"[*] 已通过传入的 ICCID ({iccid_str}) 派生密钥")
        except Exception as e:
            print(f"[-] ICCID 格式或密钥计算错误: {e}")
            sys.exit(1)
    else:
        # 默认从密文 0x120 偏移处获取 10 字节 XOR 密钥
        # By default, extract 10-byte XOR key from ciphertext at offset 0x120
        key = raw_data[0x120 : 0x120 + 10]
        print(f"[*] 未指定 ICCID，已自动从 0x120 偏移处提取密钥")

    key_hex = ' '.join(f'{b:02X}' for b in key)
    print(f"[*] 解密密钥 (HEX): {key_hex}")

    # XOR 解密 0x100 到 0x5FF 区域
    # XOR decrypt 0x100 to 0x5FF
    decrypted_data = bytearray(raw_data)
    for i in range(0x100, 0x600):
        decrypted_data[i] = raw_data[i] ^ key[(i + 2) % 10]

    # 基于明文校验 Checksum (0x0BF8)
    # Checksum validation based on plaintext
    MAIN_OFFSET = 0x100
    MAIN_LENGTH = 0x500
    EXTRA_OFFSET = 0x700
    EXTRA_LENGTH = 0x20
    INITIAL = 0x28

    main_sum = sum(decrypted_data[MAIN_OFFSET : MAIN_OFFSET + MAIN_LENGTH])
    extra_sum = sum(decrypted_data[EXTRA_OFFSET : EXTRA_OFFSET + EXTRA_LENGTH])
    calc_checksum = (main_sum + extra_sum + INITIAL) & 0xFF
    stored_checksum = decrypted_data[0x0BF8]

    if calc_checksum == stored_checksum:
        print(f"[+] 校验和验证成功: 0x{stored_checksum:02X} == 0x{calc_checksum:02X}")
    else:
        print(f"[!] 警告: 校验和不匹配 (文件记录: 0x{stored_checksum:02X}, 计算所得: 0x{calc_checksum:02X})，请确认密钥是否正确。")

    # 构造输出文件名
    # Construct output filenames
    basename = os.path.splitext(os.path.basename(input_file))[0]
    match = re.match(r'^([0-9A-Fa-f]{15,}F)', basename, re.IGNORECASE)
    if match:
        prefix = match.group(1).upper()
    else:
        prefix = re.sub(r'_(encrypted|decrypted)$', '', basename, flags=re.IGNORECASE)

    if not prefix.upper().endswith("_6FE9"):
        base_prefix = f"{prefix}_6FE9"
    else:
        base_prefix = prefix

    dec_bin_file = f"{base_prefix}_decrypted.bin"
    parsed_txt_file = f"{base_prefix}_parsed.txt"

    # 1. 导出解密 dump bin
    # 1. Export decrypted dump bin
    with open(dec_bin_file, 'wb') as f:
        f.write(decrypted_data)

    # 2. 构造解析输出文本
    # 2. Construct parsed output text
    lines = []
    lines.append(f"Decryption Key (HEX): {key_hex}")
    lines.append(f"0x0000: 0x{decrypted_data[0]:02X}")
    lines.append("")
    
    # ==== EZAppli 部分 ====
    # ==== EZAppli Section ====
    lines.append("EZAppli")
    lines.append(f"0x0100 ADS, User-ID: {get_string(decrypted_data, 0x0100, 0x0140)}")
    lines.append(f"0x0140 ADS, User-Password: {get_string(decrypted_data, 0x0140, 0x0160)}")
    
    ip_0160 = get_ip_str(decrypted_data, 0x0160)
    if ip_0160: lines.append(f"0x0160 ADS, General IP Address: {ip_0160}")
    
    ip_0164 = get_ip_str(decrypted_data, 0x0164)
    if ip_0164: lines.append(f"0x0164 ADS, Enterprise IP Address: {ip_0164}")
    
    ip_0168 = get_ip_str(decrypted_data, 0x0168)
    if ip_0168: lines.append(f"0x0168 Validation Server, IP Address: {ip_0168}")
    
    lines.append(f"0x0170 ID, SubscriberID: {get_string(decrypted_data, 0x0170, 0x0200)}")
    lines.append(f"0x0200 BREW.net, User-ID: {get_string(decrypted_data, 0x0200, 0x0240)}")
    lines.append(f"0x0240 BREW.net, User-Password: {get_string(decrypted_data, 0x0240, 0x0260)}")
    
    ip_0260 = get_ip_str(decrypted_data, 0x0260)
    if ip_0260: lines.append(f"0x0260 Location Server, IP Address: {ip_0260}")
    
    lines.append("")
    # ==== EZWeb 部分 ====
    # ==== EZWeb Section ====
    lines.append("EZWeb")
    lines.append(f"0x0300 E-Mail, Network Login ID: {get_string(decrypted_data, 0x0300, 0x0340)}")
    lines.append(f"0x0340 E-Mail, Network Password: {get_string(decrypted_data, 0x0340, 0x0360)}")
    
    ip_0360 = get_ip_str(decrypted_data, 0x0360)
    if ip_0360: lines.append(f"0x0360 Unknown IP Address: {ip_0360}")
    
    ip_0364 = get_ip_str(decrypted_data, 0x0364)
    if ip_0364: lines.append(f"0x0364 Unknown IP Address: {ip_0364}")
    
    lines.append(f"0x0370 Unknown URL: {get_string(decrypted_data, 0x0370, 0x03B0)}")
    lines.append(f"0x03B0 EZweb Topmenu URL: {get_string(decrypted_data, 0x03B0, 0x0460)}")
    
    ip_0460 = get_ip_str(decrypted_data, 0x0460)
    if ip_0460: lines.append(f"0x0460 E-Mail, Server IP Address: {ip_0460}")
    
    lines.append(f"0x0470 E-Mail, Mail Login ID: {get_string(decrypted_data, 0x0470, 0x04B0)}")
    lines.append(f"0x04B0 E-Mail, Server Config URL: {get_string(decrypted_data, 0x04B0, 0x0500)}")
    lines.append(f"0x0500 E-Mail, E-Mail Address: {get_string(decrypted_data, 0x0500, 0x0580)}")
    
    lines.append("")
    # ==== 尾部 / 未知项 ====
    # ==== Footer / Unknowns ====
    b_0580 = decrypted_data[0x0580]
    str_0580 = get_string(decrypted_data, 0x0581, 0x0600)
    lines.append(f"0x0580 Phone Number: 0x{b_0580:02X} {str_0580}".strip())
    
    lines.append("")
    lines.append(f"0x0708 Unknown (HEX): {get_hex(decrypted_data, 0x0708, 4)}")
    lines.append(f"0x070C Unknown (HEX): {get_hex(decrypted_data, 0x070C, 16)}")
    lines.append(f"0x071C Unknown (HEX): {get_hex(decrypted_data, 0x071C, 4)}")
    
    val_0bf8 = decrypted_data[0x0BF8] if len(decrypted_data) > 0x0BF8 else 0xFF
    lines.append(f"0x0BF8 Checksum: 0x{val_0bf8:02X}")

    with open(parsed_txt_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"\n[+] 解密与解析完成！")
    print(f"  已生成文件: \n  1. {dec_bin_file}\n  2. {parsed_txt_file}\n")

if __name__ == '__main__':
    main()