import sys

# ISO 7816-3 FI(时钟速率转换因子) 映射表 -> (F值(16进制), 最大频率MHz(10进制))
# ISO 7816-3 FI (Clock rate conversion factor) mapping table -> (F value (hex), max frequency MHz (dec))
FI_TABLE = {
    0x0: (0x174, 4),     # 372, 4 MHz
    0x1: (0x174, 5),     # 372, 5 MHz
    0x2: (0x22E, 6),     # 558, 6 MHz
    0x3: (0x2E8, 8),     # 744, 8 MHz
    0x4: (0x45C, 12),    # 1116, 12 MHz
    0x5: (0x5D0, 16),    # 1488, 16 MHz
    0x6: (0x744, 20),    # 1860, 20 MHz
    0x9: (0x200, 5),     # 512, 5 MHz
    0xA: (0x300, 7.5),   # 768, 7.5 MHz
    0xB: (0x400, 10),    # 1024, 10 MHz
    0xC: (0x600, 15),    # 1536, 15 MHz
    0xD: (0x800, 20)     # 2048, 20 MHz
}

# ISO 7816-3 DI(波特率调整因子) 映射表 -> D值
# ISO 7816-3 DI (Baud rate adjustment factor) mapping table -> D value
DI_TABLE = {
    0x1: 1,
    0x2: 2,
    0x3: 4,
    0x4: 8,
    0x5: 16, 
    0x6: 32, 
    0x7: 64, 
    0x8: 12, 
    0x9: 20  
}

def analyze_atr(atr_hex_str):
    # 清理并转换输入字符串
    # Clean up and convert input string
    atr_hex_str = atr_hex_str.replace(" ", "").upper()
    if len(atr_hex_str) % 2 != 0:
        print("错误: ATR长度无效！")
        return

    try:
        atr = [int(atr_hex_str[i:i+2], 16) for i in range(0, len(atr_hex_str), 2)]
    except ValueError:
        print("错误: 包含非16进制字符！")
        return

    if len(atr) < 2:
        print("错误: ATR过短！")
        return

    print("=" * 60)
    print(f"原始 ATR 输入 (Hex): {atr_hex_str}")
    print("=" * 60)
    print("\n[1] 每一位及对应名称:")
    
    parsed_bytes = []
    
    p = 0
    TS = atr[p]
    parsed_bytes.append(("TS", TS))
    p += 1
    
    T0 = atr[p]
    parsed_bytes.append(("T0", T0))
    p += 1
    
    K = T0 & 0x0F
    Y = T0 >> 4
    
    interface_bytes_dict = {}
    i = 1
    has_protocol_other_than_T0 = False
    
    while Y > 0 and p < len(atr):
        if Y & 0x1:
            name = f'TA{i}'
            interface_bytes_dict[name] = atr[p]
            parsed_bytes.append((name, atr[p]))
            p += 1
        if Y & 0x2:
            name = f'TB{i}'
            interface_bytes_dict[name] = atr[p]
            parsed_bytes.append((name, atr[p]))
            p += 1
        if Y & 0x4:
            name = f'TC{i}'
            interface_bytes_dict[name] = atr[p]
            parsed_bytes.append((name, atr[p]))
            p += 1
        if Y & 0x8:
            name = f'TD{i}'
            td_val = atr[p]
            interface_bytes_dict[name] = td_val
            parsed_bytes.append((name, td_val))
            Y = td_val >> 4
            protocol_t = td_val & 0x0F
            if protocol_t > 0x0:
                has_protocol_other_than_T0 = True
            p += 1
        else:
            Y = 0
        i += 1
        
    hist_bytes = []
    for h in range(K):
        if p < len(atr):
            name = f'H{h+1}'
            hist_bytes.append(atr[p])
            parsed_bytes.append((name, atr[p]))
            p += 1
            
    TCK = None
    if p < len(atr):
        TCK = atr[p]
        parsed_bytes.append(("TCK", TCK))
    
    # 打印名称列表 (使用一致的2位16进制大写输出)
    # Print list of byte names (using consistent 2-digit uppercase hex)
    for idx, (name, val) in enumerate(parsed_bytes):
        print(f"  Byte 0x{idx:02X}: 0x{val:02X} -> {name}")

    print("\n" + "=" * 60)
    print("[2] ATR 详细分析:")
    
    # 分析 TS
    # Analyze TS
    if TS == 0x3B:
        print("  [+] TS: 0x3B -> 正向约定 (Direct Convention)，智能卡通常使用。高电平为 1。")
    elif TS == 0x3F:
        print("  [+] TS: 0x3F -> 反向约定 (Inverse Convention)。低电平为 1。")
    else:
        print(f"  [+] TS: 0x{TS:02X} -> 未知约定！")
        
    # 分析 T0 (输出10进制历史字节数)
    # Analyze T0 (output decimal count of historical bytes)
    print(f"  [+] T0: 0x{T0:02X} -> 历史字节数量: {K} 个")
    
    # 分析接口字节 TA1
    # Analyze interface byte TA1
    if 'TA1' in interface_bytes_dict:
        ta1 = interface_bytes_dict['TA1']
        fi = ta1 >> 4
        di = ta1 & 0x0F
        f_val, f_max = FI_TABLE.get(fi, (0x174, 4))
        d_val = DI_TABLE.get(di, 1)
        print(f"  [+] TA1: 0x{ta1:02X}")
        # 人类易读的值用 10进制 呈现
        # Human-readable values presented in decimal
        print(f"      - FI (时钟速率转换因子): 0x{fi:X} -> 对应 F = 0x{f_val:X} ({f_val}), 最大工作频率 f(max) = {f_max} MHz")
        print(f"      - DI (波特率调整因子): 0x{di:X} -> 对应 D = 0x{d_val:X} ({d_val})")
        
        base_clock = 3571200
        baud_rate = (base_clock // f_val) * d_val
        print(f"      - 在时钟频率 3.5712 MHz 下，支持的波特率速率约为: {baud_rate} bps")
    else:
        print("  [+] TA1: 不存在 -> 使用默认速率，F = 0x174 (372), D = 0x1 (1), 默认波特率约为 9600 bps")
        
    # 分析接口字节 TB1
    # Analyze interface byte TB1
    if 'TB1' in interface_bytes_dict:
        tb1 = interface_bytes_dict['TB1']
        i_current = tb1 >> 5
        p1 = tb1 & 0x1F
        print(f"  [+] TB1: 0x{tb1:02X}")
        print(f"      - 最大编程电流指示 (I): 0x{i_current:X}")
        print(f"      - 编程电压指示 (PI1): 0x{p1:02X}")
        
    # 分析接口字节 TC1
    # Analyze interface byte TC1
    if 'TC1' in interface_bytes_dict:
        tc1 = interface_bytes_dict['TC1']
        print(f"  [+] TC1: 0x{tc1:02X}")
        if tc1 == 0xFF:
            print("      - N (额外保护时间): 0xFF -> 使用最小保护时间。")
        else:
            print(f"      - N (额外保护时间): 0x{tc1:02X}")
            
    # 查找支持的协议
    # Find supported protocols
    supported_protocols = set()
    for name, val in interface_bytes_dict.items():
        if name.startswith('TD'):
            supported_protocols.add(val & 0x0F)
    
    if not supported_protocols:
        supported_protocols.add(0x0)
        
    prot_str = ", ".join([f"T=0x{p:X}" for p in supported_protocols])
    print(f"  [+] 支持的协议类型: {prot_str}")
    
    # 分析历史字节
    # Analyze historical bytes
    if hist_bytes:
        hex_hist = " ".join([f"0x{h:02X}" for h in hist_bytes])
        print(f"  [+] 历史字节 (共 {len(hist_bytes)} 字节): {hex_hist}")
        
    print("\n" + "=" * 60)
    print("[3] XOR 校验计算 (去除第一位 TS，不含 TCK 本身):")
    
    xor_result = 0x0
    xor_formula = []
    
    for name, val in parsed_bytes:
        if name == "TS" or name == "TCK":
            continue
        xor_result ^= val
        xor_formula.append(f"0x{val:02X}")
        
    print(f"  计算过程: {' ^ '.join(xor_formula)}")
    print(f"  计算出的 XOR 结果: 0x{xor_result:02X}")
    
    if TCK is not None:
        print(f"  从 ATR 中解析到的 TCK: 0x{TCK:02X}")
        if xor_result == TCK:
            print("  校验结论: ✅ TCK 校验成功 (Calculated == TCK)！")
        else:
            print("  校验结论: ❌ TCK 校验失败！")
    else:
        print("  从 ATR 中解析到的 TCK: 无 (此 ATR 未提供 TCK 位)")
        if has_protocol_other_than_T0:
            print("  校验结论: ⚠️ 警告！该卡声明了 T>0 的协议，必须包含 TCK 位，但未检测到。")
        else:
            print("  校验结论: ℹ️ 该卡仅使用 T=0x0 协议，无需 TCK 位，属正常现象。")
            
if __name__ == "__main__":
    if len(sys.argv) > 1:
        atr_input = sys.argv[1]
    else:
        print("未输入ATR，使用默认例子演示...")
        atr_input = "3B9611801FC3D0001C000F0018"
        
    analyze_atr(atr_input)