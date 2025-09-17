"""
emulation_analyzer.py: The core of the automatic analysis.
Uses Unicorn Engine to emulate the binary, discover code, data, and functions.
"""

import sys
import logging
from collections import defaultdict
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_PROT_ALL, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
from database import AnalysisDatabase, ITEM_TYPE_CODE, ITEM_TYPE_DATA, ITEM_TYPE_UNDEFINED, DATA_TYPE_BYTE, DATA_TYPE_WORD, DATA_TYPE_DWORD

logger = logging.getLogger(__name__)

class EmulationAnalyzer:
    def __init__(self, db: AnalysisDatabase):
        self.db = db; self.md = Cs(CS_ARCH_X86, CS_MODE_16); self.md.detail = True
        self.uc = None; self.discovered_code = set(); self.call_targets = {self.db.entry_point}
        self.mem_access_log = defaultdict(set); self.instruction_count = 0

    def analyze(self, timeout_ms=5000):
        logger.info("Starting emulation-driven analysis...")
        self._initial_disassembly_pass()
        try:
            self._setup_unicorn()
            if self.uc is None: return
            self._setup_hooks()
            logger.info(f"Emulating from entry point {self.db.entry_point:05X}...")
            self.uc.emu_start(self.db.entry_point, -1, timeout=timeout_ms * 1000, count=500000)
        except Exception as e:
            logger.info(f"Emulation stopped: {e}"); logger.debug(f"Emulation traceback: {sys.exc_info()}")
        logger.info("Emulation finished. Post-processing results...")
        logger.info(f"Total instructions executed: {self.instruction_count}")
        if self.instruction_count < 10: logger.warning("Very few instructions were executed. Analysis may be incomplete.")
        self._post_process_memory_accesses(); self._discover_functions(); self._name_unnamed_items()
        logger.info("Emulation analysis complete.")

    def _setup_unicorn(self):
        try:
            self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
            self.uc.mem_map(0, 1024 * 1024, UC_PROT_ALL)
            for seg in self.db.segments:
                size = seg.end_addr - seg.start_addr
                if size > 0:
                    seg_bytes = bytes([self.db.memory[addr].byte_value for addr in range(seg.start_addr, seg.end_addr) if addr in self.db.memory])
                    if seg_bytes: self.uc.mem_write(seg.start_addr, seg_bytes)
            self.uc.reg_write(UC_X86_REG_CS, self.db.initial_cs); self.uc.reg_write(UC_X86_REG_IP, self.db.initial_ip)
            self.uc.reg_write(UC_X86_REG_SS, self.db.initial_ss); self.uc.reg_write(UC_X86_REG_SP, self.db.initial_sp)
            self.uc.reg_write(UC_X86_REG_DS, self.db.initial_cs); self.uc.reg_write(UC_X86_REG_ES, self.db.initial_cs)
        except Exception as e:
            logger.error(f"Failed during Unicorn setup: {e}"); self.uc = None

    def _setup_hooks(self):
        self.uc.hook_add(UC_HOOK_CODE, self._instruction_hook)
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._mem_access_hook)
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt_hook)
        # self.uc.hook_add(UC_HOOK_IO_READ, self._io_read_hook); self.uc.hook_add(UC_HOOK_IO_WRITE, self._io_write_hook)

    def _interrupt_hook(self, uc, intno, user_data):
        if intno == 0x21 and uc.reg_read(UC_X86_REG_AH) == 0x4C:
            logger.info("Program requested exit via INT 21h, AH=4Ch. Stopping emulation.")
            uc.emu_stop()

    def _io_read_hook(self, uc, port, size, user_data):
        logger.debug(f"Ignoring I/O port READ from port {port:04X}h, returning 0"); return 0
    def _io_write_hook(self, uc, port, size, value, user_data):
        logger.debug(f"Ignoring I/O port WRITE to port {port:04X}h (value: {value:X})")

    def _instruction_hook(self, uc, address, size, user_data):
        if address in self.discovered_code: return
        self.discovered_code.add(address); self.instruction_count += 1
        info = self.db.get_address_info(address)
        if not info or not info.instruction: return
        insn = info.instruction
        is_flow_control = insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL) or insn.group(CS_GRP_RET)
        if insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL):
            op, target = insn.operands[-1], 0
            if op.type == X86_OP_IMM: target = op.imm
            elif op.type == X86_OP_REG:
                reg_id = self._get_uc_reg_id(insn.reg_name(op.reg))
                if reg_id != UC_X86_REG_INVALID:
                    target = self.db.to_linear_address(uc.reg_read(UC_X86_REG_CS), uc.reg_read(reg_id))
            if target and self.db.get_address_info(target):
                if target not in info.xrefs_to: info.xrefs_to.append(target)
                target_info = self.db.get_address_info(target)
                if target_info:
                    if address not in target_info.xrefs_from: target_info.xrefs_from.append(address)
                    target_info.item_type = ITEM_TYPE_CODE
                    if insn.group(CS_GRP_CALL): self.call_targets.add(target)
        if not is_flow_control:
            next_addr = address + size
            if self.db.get_address_info(next_addr): self.db.get_address_info(next_addr).item_type = ITEM_TYPE_CODE

    def _mem_access_hook(self, uc, access, address, size, value, user_data): self.mem_access_log[address].add(size)
    def _initial_disassembly_pass(self):
        disasm_hits = 0
        for addr, info in self.db.memory.items():
            if info.item_type != ITEM_TYPE_DATA and not info.instruction:
                code_bytes = bytes([self.db.memory[a].byte_value for a in range(addr, addr + 15) if a in self.db.memory])
                try:
                    insn = next(self.md.disasm(code_bytes, addr, count=1))
                    info.instruction, info.item_size, info.item_type = insn, insn.size, ITEM_TYPE_CODE
                    for i in range(1, insn.size):
                        if self.db.get_address_info(addr + i): self.db.get_address_info(addr + i).item_type = ITEM_TYPE_CODE
                    disasm_hits += 1
                    if disasm_hits % 10000 == 0:
                        logger.debug(f"Initial disasm: {disasm_hits} instructions found so far")
                except StopIteration: pass
        logger.debug(f"Initial disassembly pass: {disasm_hits} instructions identified")

    def _post_process_memory_accesses(self):
        data_items = 0
        dword_count, word_count, byte_count = 0, 0, 0
        for addr, sizes in self.mem_access_log.items():
            info = self.db.get_address_info(addr)
            if info and info.item_type != ITEM_TYPE_CODE:
                info.item_type = ITEM_TYPE_DATA
                max_size = max(sizes) if sizes else 1
                if max_size == 4:
                    info.data_type, info.item_size = DATA_TYPE_DWORD, 4
                    dword_count += 1
                elif max_size == 2:
                    info.data_type, info.item_size = DATA_TYPE_WORD, 2
                    word_count += 1
                else:
                    info.data_type, info.item_size = DATA_TYPE_BYTE, 1
                    byte_count += 1
                data_items += 1
        logger.debug(f"Post-process: {data_items} data items classified ({dword_count} DWORD, {word_count} WORD, {byte_count} BYTE); {len(self.mem_access_log)} access sites")

    def _discover_functions(self):
        functions_discovered = 0
        for start_addr in sorted(list(self.call_targets)):
            end_addr = self._trace_function_end(start_addr)
            if end_addr > start_addr:
                self.db.add_function(start_addr, end_addr)
                functions_discovered += 1
                logger.debug(f"Discovered function at {start_addr:05X} to {end_addr:05X}")
        logger.debug(f"Function discovery: {functions_discovered} functions added; {len(self.call_targets)} call targets processed")

    def _trace_function_end(self, start_addr):
        addr, visited, max_size = start_addr, {start_addr}, 8192
        while addr < start_addr + max_size:
            info = self.db.get_address_info(addr)
            if not info or not info.instruction: return addr
            insn = info.instruction
            if insn.group(CS_GRP_RET): return addr + insn.size
            if addr != start_addr and addr in self.call_targets: return addr
            if insn.group(CS_GRP_JUMP) and len(insn.operands) > 0 and insn.operands[0].type == X86_OP_IMM:
                target = insn.operands[0].imm
                if start_addr <= target < start_addr + max_size and target not in visited:
                    addr = target; visited.add(addr); continue
            addr += insn.size
            if addr in visited: return addr
        return start_addr + max_size

    def _name_unnamed_items(self):
        unnamed_data = 0
        unnamed_unk = 0
        for addr, info in self.db.memory.items():
            if not info.label:
                if info.item_type == ITEM_TYPE_DATA:
                    if info.data_type == DATA_TYPE_DWORD: info.label = f"dword_{addr:X}"
                    elif info.data_type == DATA_TYPE_WORD: info.label = f"word_{addr:X}"
                    else: info.label = f"byte_{addr:X}"
                    unnamed_data += 1
                elif info.item_type == ITEM_TYPE_UNDEFINED:
                    info.label = f"unk_{addr:X}"
                    unnamed_unk += 1
        logger.debug(f"Naming: {unnamed_data} data items, {unnamed_unk} undefined items labeled")

    def _get_uc_reg_id(self, reg_name):
        reg_map = { "ax": UC_X86_REG_AX, "bx": UC_X86_REG_BX, "cx": UC_X86_REG_CX, "dx": UC_X86_REG_DX, "sp": UC_X86_REG_SP, "bp": UC_X86_REG_BP, "si": UC_X86_REG_SI, "di": UC_X86_REG_DI, "ip": UC_X86_REG_IP, "cs": UC_X86_REG_CS, "ds": UC_X86_REG_DS, "es": UC_X86_REG_ES, "ss": UC_X86_REG_SS }
        return reg_map.get(reg_name.lower(), UC_X86_REG_INVALID)