#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import re

def parse_apdu_log(filepath):
    """
    从通信日志中提取 6FE9 文件的二进制块
    Extract 6FE9 binary chunk from communication logs
    """
    raw_data = bytearray()
    max_written = 0
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if '6FE9' in line and 'ReadBinary' in line and 'Offset=' in line:
                match = re.search(r'Offset=(\d+):\s*([0-9A-Fa-f\s]+)', line)
                if match:
                    offset = int(match.group(1))
                    hex_data = match.group(2).replace(' ', '').strip()
                    chunk = bytes.fromhex(hex_data)
                    
                    if offset + len(chunk) > len(raw_data):
                        raw_data.extend(bytearray(offset + len(chunk) - len(raw_data)))
                        
                    raw_data[offset:offset+len(chunk)] = chunk
                    max_written = max(max_written, offset + len(chunk))
                    
    return raw_data[:max_written] if max_written > 0 else None

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
        print("用法: python 6FE9_decrypt.py <txt_name>.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"错误: 找不到文件 '{input_file}'。")
        sys.exit(1)

    basename = os.path.splitext(os.path.basename(input_file))[0]
    # 正则匹配 ICCID 格式：15位以上十六进制数 + 'F' + '-XXX'
    # Regex match ICCID format: 15+ hex digits + 'F' + '-XXX'
    match = re.match(r'^([0-9A-Fa-f]{15,}F)-', basename, re.IGNORECASE)
    prefix = match.group(1).upper() if match else basename

    print(f"[*] 正在解析: {input_file} ...")
    raw_data = parse_apdu_log(input_file)
    
    if not raw_data:
        print("[-] 提取失败：未找到有效的 ReadBinary 数据。")
        sys.exit(1)

    # 完整 6FE9 文件大小应为 0xC00 (3072) 字节，防止最后一段没抓全导致越界报错
    # Complete 6FE9 file size should be 0xC00 (3072) bytes, preventing out-of-bounds error if not fully captured
    if len(raw_data) < 0xC00:
        raw_data.extend(bytearray(0xC00 - len(raw_data)))

    decrypted_data = bytearray(raw_data)
    
    # 获取加密密钥
    # Obtain encryption key
    key = raw_data[0x120 : 0x120 + 10]
    key_hex = ' '.join(f'{b:02X}' for b in key)

    # XOR 解密 0x100 到 0x5FF 区域
    # XOR decrypt 0x100 to 0x5FF
    for i in range(0x100, 0x600):
        decrypted_data[i] = raw_data[i] ^ key[(i + 2) % 10]

    raw_bin_file = f"{prefix}_6FE9.bin"
    dec_bin_file = f"{prefix}_6FE9_decrypted.bin"
    parsed_txt_file = f"{prefix}_6FE9_parsed.txt"

    # 1. 导出原版 dump bin
    # 1. Export original dump bin
    with open(raw_bin_file, 'wb') as f: f.write(raw_data)
    # 2. 导出解密 dump bin
    # 2. Export decrypted dump bin
    with open(dec_bin_file, 'wb') as f: f.write(decrypted_data)

    # 3. 构造解析输出文本
    # 3. Construct parsed output text
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

    print(f"[+] 提取成功！解密密钥为: {key_hex}")
    print(f"  已生成文件: \n  1. {raw_bin_file}\n  2. {dec_bin_file}\n  3. {parsed_txt_file}\n")

if __name__ == '__main__':
    main()