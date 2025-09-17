"""
output_generator.py: Generates the final output files (.lst and .asm).
"""

import logging
from database import AnalysisDatabase, ITEM_TYPE_CODE, ITEM_TYPE_DATA, DATA_TYPE_ASCII, DATA_TYPE_WORD, DATA_TYPE_DWORD

logger = logging.getLogger(__name__)

class OutputGenerator:
    def __init__(self, db: AnalysisDatabase):
        self.db = db

    def _format_address(self, addr: int) -> str:
        seg_off = self.db.to_segment_offset(addr)
        return f"{seg_off[0]}:{seg_off[1]:04X}" if seg_off else f"{addr:08X}"

    def _get_data_at(self, addr: int, size: int) -> list[int]:
        return [self.db.memory[a].byte_value for a in range(addr, addr + size) if a in self.db.memory]

class LSTGenerator(OutputGenerator):
    def generate(self, filepath: str):
        logger.info(f"Generating LST file: {filepath}")
        code_count, data_count = 0, 0
        with open(filepath, 'w') as f:
            for seg in sorted(self.db.segments, key=lambda s: s.start_addr):
                logger.debug(f"Processing LST segment '{seg.name}' ({seg.start_addr:05X}-{seg.end_addr:05X})")
                f.write(f"; Segment: {seg.name} ({seg.seg_class}) at {seg.selector:04X}\n;---------------------------------------------------------------------------\n\n")
                addr = seg.start_addr
                while addr < seg.end_addr:
                    info = self.db.get_address_info(addr)
                    if not info:
                        addr += 1
                        continue
                    if info.repeatable_comment: f.write(f"\n; {info.repeatable_comment}\n")
                    if info.label: f.write(f"{self._format_address(addr)} {' ' * 10}{info.label}:\n")
                    if info.item_type == ITEM_TYPE_CODE and info.instruction:
                        line = self._format_code_line(info)
                        code_count += 1
                    elif info.item_type == ITEM_TYPE_DATA:
                        line = self._format_data_line(info)
                        data_count += 1
                    else: line = self._format_undefined_line(info)
                    f.write(line)
                    addr += info.item_size
        logger.debug(f"LST generation: {code_count} code lines, {data_count} data lines, {len(self.db.segments)} segments")

    def _format_code_line(self, info):
        addr_str, insn = self._format_address(info.address), info.instruction
        hex_bytes = ' '.join(f"{b:02X}" for b in insn.bytes).ljust(20)
        mnemonic = f"{insn.mnemonic.upper():<8}{insn.op_str}"
        line = f"{addr_str} {hex_bytes} {mnemonic}"
        if info.comment: line = f"{line.ljust(70)} ; {info.comment}"
        return line + "\n"

    def _format_data_line(self, info):
        addr_str, size = self._format_address(info.address), info.item_size
        data_bytes = self._get_data_at(info.address, size)
        if not data_bytes: return ""
        hex_bytes = ' '.join(f"{b:02X}" for b in data_bytes).ljust(20)
        if info.data_type == DATA_TYPE_ASCII:
            text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data_bytes)
            directive, value = "db", f"'{text}'"
        elif info.data_type == DATA_TYPE_DWORD:
            directive, val = "dd", sum(b << (i*8) for i, b in enumerate(data_bytes))
            value = f"0{val:X}h"
        elif info.data_type == DATA_TYPE_WORD:
            directive, val = "dw", sum(b << (i*8) for i, b in enumerate(data_bytes))
            value = f"0{val:X}h"
        else:
            directive, value = "db", f"0{data_bytes[0]:X}h"
        mnemonic = f"{directive:<8}{value}"
        line = f"{addr_str} {hex_bytes} {mnemonic}"
        if info.comment: line = f"{line.ljust(70)} ; {info.comment}"
        return line + "\n"

    def _format_undefined_line(self, info):
        addr_str, hex_byte = self._format_address(info.address), f"{info.byte_value:02X}".ljust(20)
        return f"{addr_str} {hex_byte} {'db':<8}?\n"

class ASMGenerator(OutputGenerator):
    def generate(self, filepath: str):
        logger.info(f"Generating ASM file: {filepath}")
        with open(filepath, 'w') as f:
            f.write(".MODEL SMALL\n.CODE\n\n")
            assumes = [f"{s.seg_class.lower()}:{s.name}" for s in self.db.segments]
            f.write(f"ASSUME {', '.join(assumes)}\n\n")
            for seg in sorted(self.db.segments, key=lambda s: s.start_addr):
                f.write(f"{seg.name} SEGMENT AT {seg.selector:04X}H\n")
                addr = seg.start_addr
                while addr < seg.end_addr:
                    info = self.db.get_address_info(addr)
                    if not info: addr += 1; continue
                    func = self.db.get_function_containing(addr)
                    if func and func.start_addr == addr: f.write(f"{func.name} PROC NEAR\n")
                    if info.repeatable_comment: f.write(f"\n; {info.repeatable_comment}\n")
                    if info.label and (not func or func.start_addr != addr): f.write(f"{info.label}:\n")
                    if info.item_type == ITEM_TYPE_CODE and info.instruction: line = self._format_code_line(info)
                    elif info.item_type == ITEM_TYPE_DATA: line = self._format_data_line(info)
                    else: line = self._format_data_line(info, is_undefined=True)
                    f.write(line)
                    if func and func.end_addr == addr + info.item_size: f.write(f"{func.name} ENDP\n\n")
                    addr += info.item_size
                f.write(f"{seg.name} ENDS\n\n")
            f.write("END\n")

    def _format_code_line(self, info):
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
        insn, op_strs = info.instruction, []
        for i, op in enumerate(insn.operands):
            override = self.db.operand_format_overrides.get((insn.address, i))
            if override:
                if override.format_type == 'hex': op_strs.append(f"0{op.imm:X}h"); continue
                if override.format_type == 'dec': op_strs.append(f"{op.imm}"); continue
                if override.format_type == 'offset':
                    op_strs.append(f"OFFSET {self.db.get_label_at(op.imm) or f'0{op.imm:X}h'}"); continue
            if op.type == X86_OP_IMM:
                target_label = self.db.get_label_at(op.imm)
                op_strs.append(target_label if target_label else f"0{op.imm:X}h")
            elif op.type == X86_OP_REG: op_strs.append(insn.reg_name(op.reg))
            elif op.type == X86_OP_MEM:
                mem_str = f"{ {1:'BYTE',2:'WORD',4:'DWORD'}.get(op.size,'')} PTR " if op.size > 0 else ""
                mem_str += f"[{insn.op_str.split('[',1)[-1]}"
                op_strs.append(mem_str)
        line = f"    {insn.mnemonic.upper():<8}{', '.join(op_strs)}"
        if info.comment: line = f"{line.ljust(40)} ; {info.comment}"
        return line + "\n"

    def _format_data_line(self, info, is_undefined=False):
        size, data_bytes = info.item_size, self._get_data_at(info.address, info.item_size)
        if not data_bytes: return ""
        if is_undefined: value, directive = "?", "db"
        elif info.data_type == DATA_TYPE_ASCII:
            text = ''.join(chr(b) for b in data_bytes[:-1]).replace("'", "''")
            value, directive = f"'{text}', 0", "db"
        elif info.data_type == DATA_TYPE_DWORD:
            val = sum(b << (i*8) for i, b in enumerate(data_bytes))
            value, directive = f"0{val:X}h", "dd"
        elif info.data_type == DATA_TYPE_WORD:
            val = sum(b << (i*8) for i, b in enumerate(data_bytes))
            value, directive = f"0{val:X}h", "dw"
        else:
            value, directive = f"0{data_bytes[0]:X}h", "db"
        line = f"    {directive:<8}{value}"
        if info.comment: line = f"{line.ljust(40)} ; {info.comment}"
        return line + "\n"
