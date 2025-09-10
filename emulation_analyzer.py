"""
emulation_analyzer.py: The core of the automatic analysis.
Uses Qiling to emulate the binary, discover code, data, and functions.
"""

import sys
import logging
from collections import defaultdict
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from capstone import *
from capstone.x86 import *
from database import AnalysisDatabase, ITEM_TYPE_CODE, ITEM_TYPE_DATA, ITEM_TYPE_UNDEFINED, DATA_TYPE_BYTE, DATA_TYPE_WORD, DATA_TYPE_DWORD

logger = logging.getLogger(__name__)

# Suppress noisy Qiling logging

class EmulationAnalyzer:
    def __init__(self, db: AnalysisDatabase):
        self.db = db
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)
        self.md.detail = True
        self.ql = None
        self.code_to_discover = {self.db.entry_point}
        self.discovered_code = set()
        self.call_targets = {self.db.entry_point}
        self.mem_access_log = defaultdict(set) # addr -> {size1, size2}

    def analyze(self, timeout_ms=5000):
        """
        Performs emulation-driven analysis to discover the program structure.
        """
        logger.info("Starting emulation-driven analysis...")
        
        # Initial static disassembly pass to populate instruction info
        self._initial_disassembly_pass()

        try:
            self._setup_qiling()
            self._setup_hooks()
            
            logger.info(f"Emulating from entry point {self.db.entry_point:05X}...")
            self.ql.run(begin=self.db.entry_point, timeout=timeout_ms)

        except Exception as e:
            logger.error(f"Emulation failed: {e}")
            import traceback
            logger.error(f"Emulation failure traceback: {traceback.format_exc()}")
        
        logger.info("Emulation finished. Post-processing results...")
        self._post_process_memory_accesses()
        self._discover_functions()
        self._name_unnamed_items()
        logger.info("Emulation analysis complete.")

    def _setup_qiling(self):
        self.ql = Qiling(
            [],
            archtype=QL_ARCH.X86,
            ostype=QL_OS.DOS,
            verbose=QL_VERBOSE.DEFAULT
        )
        # Map all segments from the database into Qiling's memory
        for seg in self.db.segments:
            size = seg.end_addr - seg.start_addr
            self.ql.mem.map(seg.start_addr, size)
            
            # Write the actual bytes from the database to the emulator's memory
            seg_bytes = bytes([
                self.db.memory[addr].byte_value
                for addr in range(seg.start_addr, seg.end_addr)
                if addr in self.db.memory
            ])
            self.ql.mem.write(seg.start_addr, seg_bytes)

    def _setup_hooks(self):
        self.ql.hook_code(self._instruction_hook)
        self.ql.hook_mem_read(self._mem_access_hook)
        self.ql.hook_mem_write(self._mem_access_hook)

    def _instruction_hook(self, ql, address, size):
        """Callback executed for every instruction."""
        if address in self.discovered_code:
            return
        self.discovered_code.add(address)

        info = self.db.get_address_info(address)
        if not info or not info.instruction:
            return

        insn = info.instruction
        is_flow_control = False

        if insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL):
            is_flow_control = True
            op = insn.operands[-1]
            target = 0

            if op.type == X86_OP_IMM:
                target = op.imm
            elif op.type == X86_OP_REG:
                reg_name = insn.reg_name(op.reg)
                target = ql.reg.read(reg_name)
            
            if target:
                info.xrefs_to.append(target)
                target_info = self.db.get_address_info(target)
                if target_info:
                    target_info.xrefs_from.append(address)
                    target_info.item_type = ITEM_TYPE_CODE
                    if insn.group(CS_GRP_CALL):
                        self.call_targets.add(target)

        if insn.group(CS_GRP_RET):
            is_flow_control = True

        # If it's not a terminating instruction, add the next one to the list
        if not is_flow_control:
            next_addr = address + size
            next_info = self.db.get_address_info(next_addr)
            if next_info:
                next_info.item_type = ITEM_TYPE_CODE

    def _mem_access_hook(self, ql, access, address, size, value):
        """Callback for any memory read or write."""
        self.mem_access_log[address].add(size)

    def _initial_disassembly_pass(self):
        """Disassemble everything to have instruction info ready for hooks."""
        for addr, info in self.db.memory.items():
            if info.item_type == ITEM_TYPE_CODE and not info.instruction:
                code_bytes = bytes([
                    self.db.memory[a].byte_value
                    for a in range(addr, addr + 15) if a in self.db.memory
                ])
                try:
                    insn = next(self.md.disasm(code_bytes, addr, count=1))
                    info.instruction = insn
                    info.item_size = insn.size
                    for i in range(1, insn.size):
                        next_info = self.db.get_address_info(addr + i)
                        if next_info:
                            next_info.item_type = ITEM_TYPE_CODE
                except StopIteration:
                    pass # Can't disassemble

    def _post_process_memory_accesses(self):
        """Mark all accessed memory as data in the database."""
        for addr, sizes in self.mem_access_log.items():
            info = self.db.get_address_info(addr)
            if info:
                info.item_type = ITEM_TYPE_DATA
                # Use the largest access size to determine type
                max_size = max(sizes)
                if max_size == 4:
                    info.data_type = DATA_TYPE_DWORD
                    info.item_size = 4
                elif max_size == 2:
                    info.data_type = DATA_TYPE_WORD
                    info.item_size = 2
                else:
                    info.data_type = DATA_TYPE_BYTE
                    info.item_size = 1

    def _discover_functions(self):
        """Trace from call targets to find function boundaries."""
        for start_addr in sorted(list(self.call_targets)):
            end_addr = self._trace_function_end(start_addr)
            if end_addr > start_addr:
                self.db.add_function(start_addr, end_addr)

    def _trace_function_end(self, start_addr):
        """Find the end of a function by tracing until a RET."""
        addr = start_addr
        visited = {addr}
        while True:
            info = self.db.get_address_info(addr)
            if not info or not info.instruction:
                return addr
            
            insn = info.instruction
            if insn.group(CS_GRP_RET):
                return addr + insn.size
            
            if insn.group(CS_GRP_JUMP) and insn.operands[0].type == X86_OP_IMM:
                target = insn.operands[0].imm
                # Follow jumps within a reasonable range
                if abs(target - start_addr) < 1024 and target not in visited:
                    addr = target
                    visited.add(addr)
                    continue

            addr += insn.size
            if addr in visited or addr > start_addr + 4096: # Safety break
                return addr

    def _name_unnamed_items(self):
        """Provide default IDA-style names for functions and data."""
        for addr, info in self.db.memory.items():
            if info.label:
                continue
            
            if info.item_type == ITEM_TYPE_DATA:
                if info.data_type == DATA_TYPE_DWORD:
                    info.label = f"dword_{addr:X}"
                elif info.data_type == DATA_TYPE_WORD:
                    info.label = f"word_{addr:X}"
                else:
                    info.label = f"byte_{addr:X}"
            elif info.item_type == ITEM_TYPE_UNDEFINED:
                 info.label = f"unk_{addr:X}"
