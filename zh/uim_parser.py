import re
import os
import sys

# 指令集 (INS)
# Instruction Set (INS)
INS_DICT = {
    0xA4: "SELECT FILE",
    0xC0: "GET RESPONSE",
    0xB0: "READ BINARY",
    0xB2: "READ RECORD",
    0xD6: "UPDATE BINARY",
    0xDC: "UPDATE RECORD",
    0x20: "VERIFY CHV",
    0x24: "CHANGE CHV",
    0x26: "DISABLE CHV",
    0x28: "ENABLE CHV",
    0x2C: "UNBLOCK CHV",
    0x88: "RUN GSM ALGORITHM",
    0x82: "EXTERNAL AUTHENTICATE",
    0x84: "GET CHALLENGE",
    0xF2: "STATUS",
    0x10: "TERMINAL PROFILE",
    0x12: "FETCH",
    0x14: "TERMINAL RESPONSE",
    0xC2: "ENVELOPE",
    0xDE: "COMMAND_DE",
    0x70: "MANAGE CHANNEL"
}

def parse_log():
    if len(sys.argv) < 2:
        print("请提供输入文件路径，例如: python uim_parser.py 8981300123456789013F_raw.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"找不到输入文件: {input_file}")
        sys.exit(1)

    # 处理文件名逻辑
    # Handle file name
    if "_raw" in input_file:
        output_file = input_file.replace("_raw", "_apdu_parsed_log")
    else:
        name, ext = os.path.splitext(input_file)
        output_file = f"{name}_apdu_parsed_log{ext}"

    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # 提取时间戳和HEX数据
    # Extract timestamp and HEX data
    pattern = re.compile(r'^(\d+)-\d+\s+ISO 7816.*?0x([0-9a-fA-F]+)', re.IGNORECASE)
    
    packets = []
    for line in lines:
        match = pattern.search(line.strip())
        if match:
            packets.append((match.group(1), int(match.group(2), 16)))

    if not packets:
        print("未提取到有效数据，请检查文件内容格式。")
        sys.exit(1)

    unique_file_data = {}

    with open(output_file, 'w', encoding='utf-8') as out:
        idx = 0
        
        # 1. 解析 ATR
        # 1. Parse ATR
        out.write(f"时间: {packets[0][0]}\n")
        atr_bytes = []
        while idx < len(packets) - 1:
            if packets[idx][1] in (0xA0, 0x00) and packets[idx+1][1] in INS_DICT:
                break
            atr_bytes.append(f"{packets[idx][1]:02X}")
            idx += 1
            
        out.write(f"ATR: {' '.join(atr_bytes)}\n\n")

        # 路径跟踪器
        # Path tracker
        current_df = ["3F00"]
        last_selected_id = "3F00"

        def get_full_path():
            if last_selected_id in current_df:
                return "/".join(current_df)
            else:
                return "/".join(current_df) + "/" + last_selected_id

        # 2. 解析后续 APDU 指令
        # 2. Parse subsequent APDU commands
        while idx < len(packets):
            found_header = False
            while idx < len(packets) - 4:
                b1, b2 = packets[idx][1], packets[idx+1][1]
                if b1 in (0xA0, 0x00) and b2 in INS_DICT:
                    found_header = True
                    break
                idx += 1

            if not found_header:
                break

            start_time = packets[idx][0]
            cla, ins, p1, p2, p3 = [packets[idx+i][1] for i in range(5)]
            idx += 5

            cmd_name = INS_DICT.get(ins, f"UNKNOWN_{ins:02X}")
            
            # 分类读写命令用于T=0状态机
            # Classify read/write commands for T=0 state machine
            is_write_cmd = ins in [0xA4, 0xD6, 0xDC, 0x20, 0x24, 0x26, 0x28, 0x2C, 0x88, 0x82, 0x10, 0x14, 0xC2, 0xDE]
            is_read_cmd = ins in [0xC0, 0xB0, 0xB2, 0x84, 0xF2, 0x12, 0x70]

            req_data, res_data = [], []
            sw1, sw2 = -1, -1

            # ======== 严谨的 T=0 协议 状态机 ========
            # ======== Strict T=0 Protocol State Machine ========
            while idx < len(packets) and packets[idx][1] == 0x60:
                idx += 1
            
            if idx < len(packets):
                pb = packets[idx][1]
                # 状态机：判断是跳出状态码还是下发数据 (6x, 9x且非过程字节ACK)
                # State machine: determine whether it is status code or data transmission (6x, 9x and not procedure byte ACK)
                if (pb >> 4) in (0x6, 0x9) and pb != 0x60 and pb != ins and pb != (ins ^ 0xFF):
                    sw1 = pb
                    sw2 = packets[idx+1][1] if idx+1 < len(packets) else -1
                    idx += 2
                else:
                    idx += 1 # 跳过正常的过程响应(PB) / Skip normal procedure byte (PB)
                    
                    data_len = 256 if (p3 == 0 and is_read_cmd) else p3
                    if is_write_cmd:
                        for _ in range(data_len):
                            if idx < len(packets): req_data.append(packets[idx][1]); idx += 1
                    elif is_read_cmd:
                        for _ in range(data_len):
                            if idx < len(packets): res_data.append(packets[idx][1]); idx += 1
                    
                    while idx < len(packets) and packets[idx][1] == 0x60:
                        idx += 1
                        
                    if idx + 1 < len(packets):
                        sw1, sw2 = packets[idx][1], packets[idx+1][1]
                        idx += 2
            # ========================================

            # 写入主解析日志
            # Write to main parsed log
            out.write(f"时间: {start_time}\n")
            out.write(f"指令头: {cla:02X} {ins:02X} {p1:02X} {p2:02X} {p3:02X}  ==> {cmd_name}\n")

            if ins == 0xA4 and len(req_data) >= 2:
                file_id = f"{req_data[0]:02X}{req_data[1]:02X}"
                last_selected_id = file_id
                out.write(f"选择文件: {file_id}\n")

                if file_id == "3F00":
                    current_df = ["3F00"]
                elif file_id.startswith("7F") or file_id.startswith("5F"):
                    if "3F00" not in current_df: current_df = ["3F00"]
                    if len(current_df) > 1:
                        current_df[1] = file_id
                    else:
                        current_df.append(file_id)

            out.write(f"操作路径: {get_full_path()}\n")

            if req_data:
                out.write(f"手机->UIM (0x{len(req_data):02X}): {' '.join([f'{x:02X}' for x in req_data])}\n")
            if res_data:
                out.write(f"UIM->手机 (0x{len(res_data):02X}): {' '.join([f'{x:02X}' for x in res_data])}\n")

            if sw1 != -1 and sw2 != -1:
                out.write(f"卡片状态: SW1={sw1:02X} SW2={sw2:02X}\n")
                
            out.write("\n")

            # ======== 收集全量去重数据供底部输出 ========
            # ======== Collect full deduplicated data for summary output at bottom ========
            active_data = req_data if is_write_cmd else res_data
            if ins != 0xA4 and active_data: 
                if ins == 0xB0: op_tag = f"ReadBinary,Offset={(p1 << 8) | p2}"
                elif ins == 0xB2: op_tag = f"ReadRecord,Nr={p1},Mode={p2}"
                elif ins == 0xD6: op_tag = f"UpdateBinary,Offset={(p1 << 8) | p2}"
                elif ins == 0xDC: op_tag = f"UpdateRecord,Nr={p1},Mode={p2}"
                elif ins == 0xC0: op_tag = "GetResponse"
                else: 
                    op_tag = cmd_name.replace(" ", "_")
                    if p1 != 0 or p2 != 0:
                        op_tag += f",P1={p1:02X},P2={p2:02X}"
                
                data_hex_str = " ".join([f"{x:02X}" for x in active_data])
                summary_line = f"{get_full_path()} {len(active_data)}Bytes {op_tag}: {data_hex_str}"
                unique_file_data[summary_line] = True

        # 3. 输出汇总信息
        # 3. Output summary information
        for line in unique_file_data.keys():
            out.write(line + "\n")

    print(f"解析完成！请查看 {output_file}")

if __name__ == '__main__':
    parse_log()