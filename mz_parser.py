import struct
from database import Database
from collections import Counter
import math
from utils import handle_error

class MZParser:
    def __init__(self, binary):
        self.binary = binary

    def parse(self):
        try:
            if len(self.binary) < 64 or self.binary[:2] != b'MZ':
                raise ValueError("Invalid MZ/EXE signature or file too short")

            # Full MZ header parsing
            header = {}
            header['pages'] = struct.unpack('<H', self.binary[2:4])[0]
            header['logical_pages'] = struct.unpack('<H', self.binary[4:6])[0]
            header['num_relocs'] = struct.unpack('<H', self.binary[6:8])[0]
            header['header_paras'] = struct.unpack('<H', self.binary[8:10])[0]
            header['min_paras'] = struct.unpack('<H', self.binary[10:12])[0]
            header['max_paras'] = struct.unpack('<H', self.binary[12:14])[0]
            header['ss'] = struct.unpack('<H', self.binary[14:16])[0]
            header['sp'] = struct.unpack('<H', self.binary[16:18])[0]
            header['csum'] = struct.unpack('<H', self.binary[18:20])[0]
            header['ip'] = struct.unpack('<H', self.binary[20:22])[0]
            header['cs'] = struct.unpack('<H', self.binary[22:24])[0]
            header['reloc_offset'] = struct.unpack('<H', self.binary[24:26])[0]
            header['overlay_num'] = struct.unpack('<H', self.binary[26:28])[0]
            header['filler'] = self.binary[28:32]  # 4 bytes
            header['min_alloc'] = struct.unpack('<H', self.binary[32:34])[0]
            header['max_alloc'] = struct.unpack('<H', self.binary[34:36])[0]
            header['ssx'] = struct.unpack('<H', self.binary[36:38])[0]
            header['spx'] = struct.unpack('<H', self.binary[38:40])[0]
            header['cx'] = struct.unpack('<H', self.binary[40:42])[0]
            header['ipx'] = struct.unpack('<H', self.binary[42:44])[0]
            header['max_stack'] = struct.unpack('<H', self.binary[44:46])[0]
            header['checksum'] = struct.unpack('<H', self.binary[46:48])[0]
            header['oem_id'] = struct.unpack('<H', self.binary[48:50])[0]
            header['oem_info'] = struct.unpack('<H', self.binary[50:52])[0]
            header['res1'] = self.binary[52:64]  # 12 bytes reserved

            header_size = header['header_paras'] * 16
            image_size = header['pages'] * 512 - header_size
            if image_size > len(self.binary):
                image_size = len(self.binary)

            # Entry point calculation
            entry_seg = header['cs']
            entry_off = header['ip']
            entry_addr = (entry_seg << 4) + entry_off

            # Create DB
            db = Database('analysis.db')

            # Parse relocation table if present
            reloc_start = header['reloc_offset']
            reloc_end = reloc_start + (header['num_relocs'] * 2)
            relocs = []
            if reloc_start > 0 and reloc_end <= len(self.binary):
                for i in range(header['num_relocs']):
                    offset = struct.unpack('<H', self.binary[reloc_start + i*2 : reloc_start + i*2 + 2])[0]
                    relocs.append(offset)
                for reloc in relocs:
                    db.execute("INSERT INTO relocations (addr, offset) VALUES (?, ?)",
                               ((entry_seg << 4) + reloc, reloc))

            # Define segments based on MZ structure
            # Code segment starting at entry or 0x10000 typical for EXE
            code_start = max(0x10000, entry_addr & 0xF0000)  # Align to segment
            code_end = code_start + image_size // 2  # Approximate
            db.execute("INSERT INTO segments (start_addr, end_addr, class, type) VALUES (?, ?, ?, ?)",
                       (code_start, code_end, 'CODE', 'code'))

            # Data segment (after code or from overlay)
            data_start = code_end
            data_end = data_start + 0x10000  # Approximate data

            # Classify segments using entropy
            def compute_entropy(start, end):
                if end - start > len(self.binary):
                    return 0
                data = self.binary[start:end]
                if len(data) == 0:
                    return 0
                counts = Counter(data)
                if not counts:
                    return 0
                probs = [count / len(data) for count in counts.values()]
                entropy = -sum(p * math.log2(p) for p in probs if p > 0)
                return entropy

            # Classify code segment
            code_entropy = compute_entropy(code_start, min(code_end, len(self.binary)))
            code_class = 'CODE' if code_entropy > 6.5 else 'DATA' if code_entropy < 3.0 else 'UNKNOWN'
            db.execute("INSERT OR REPLACE INTO segments (start_addr, end_addr, class, type, entropy) VALUES (?, ?, ?, ?, ?)",
                       (code_start, code_end, code_class, 'code', code_entropy))

            # Classify data segment
            data_entropy = compute_entropy(data_start, min(data_end, len(self.binary)))
            data_class = 'DATA' if data_entropy < 3.0 else 'CODE' if data_entropy > 6.5 else 'UNKNOWN'
            db.execute("INSERT OR REPLACE INTO segments (start_addr, end_addr, class, type, entropy) VALUES (?, ?, ?, ?, ?)",
                       (data_start, data_end, data_class, 'data', data_entropy))

            # Stack segment (from header ss/sp)
            stack_start = (header['ss'] << 4)
            stack_end = stack_start + (header['sp'] or 0x1000)
            db.execute("INSERT INTO segments (start_addr, end_addr, class, type) VALUES (?, ?, ?, ?)",
                       (stack_start, stack_end, 'STACK', 'stack'))

            # Re-classify stack if needed
            stack_entropy = compute_entropy(stack_start, min(stack_end, len(self.binary)))
            stack_class = 'STACK' if stack_entropy < 2.0 else 'DATA'
            db.execute("UPDATE segments SET class = ?, entropy = ? WHERE start_addr = ?",
                       (stack_class, stack_entropy, stack_start))

            # Insert entry point as symbol
            db.execute("INSERT INTO symbols (addr, name) VALUES (?, ?)", (entry_addr, 'start'))

            # Mark executable based on class
            db.execute("UPDATE segments SET executable = 1 WHERE class IN ('CODE', 'EXEC')")
            db.execute("UPDATE segments SET executable = 0 WHERE class IN ('DATA', 'STACK', 'UNKNOWN')")

            print(f"MZ parsing complete: entry at {hex(entry_addr)}, {header['num_relocs']} relocs, segments added")
            return db
        
        except struct.error as e:
            handle_error(f"MZ unpack error (invalid binary format): {e}", e)
            raise ValueError("Failed to parse MZ header - possibly corrupted or non-MZ file")
        except Exception as e:
            handle_error(f"MZ parse error: {e}", e)
            raise