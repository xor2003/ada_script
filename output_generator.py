import logging
import os
from capstone import Cs, CS_ARCH_X86, CS_MODE_16, x86_const

logger = logging.getLogger(__name__)

class LSTGenerator:
    def __init__(self, db):
        self.db = db
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)

    def generate(self, path):
        try:
            with open(path, 'w') as f:
                f.write("Ada Script LST Output\n")
                f.write("===================\n\n")
                if not hasattr(self.db, 'memory') or not self.db.memory:
                    logger.info("LST generation skipped: memory is empty.")
                    return

                sorted_addrs = sorted(self.db.memory.keys())
                start_addr = sorted_addrs[0]
                end_addr = sorted_addrs[-1]
                
                mem_bytes = bytearray()
                for i in range(start_addr, end_addr + 1):
                    info = self.db.memory.get(i)
                    mem_bytes.append(info.byte_value if info else 0)

                for inst in self.md.disasm(bytes(mem_bytes), start_addr):
                    addr = inst.address
                    label = self.db.get_label_at(addr)
                    comment = self.db.get_address_info(addr).comment

                    # Print label if it exists
                    if label:
                        f.write(f"{label}:\n")

                    # Format operands with labels
                    op_str = inst.op_str
                    for op in inst.operands:
                        if op.type == x86_const.X86_OP_IMM:
                            target_label = self.db.get_label_at(op.imm)
                            if target_label:
                                op_str = op_str.replace(hex(op.imm), target_label)
                    
                    hex_bytes = inst.bytes.hex().upper()
                    line = f"{addr:04X}: {hex_bytes:<12} {inst.mnemonic:<8} {op_str}"
                    
                    if comment:
                        line += f"\t; {comment}"
                    
                    f.write(line + "\n")

                logger.info(f"LST generated: {path}")
        except Exception as e:
            logger.error(f"Error generating LST: {e}")

class ASMGenerator:
    def __init__(self, db):
        self.db = db
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)

    def generate(self, path):
        try:
            with open(path, 'w') as f:
                f.write("Ada Script ASM Output\n")
                f.write("====================\n\n")
                if hasattr(self.db, 'entry_point'):
                    f.write(f"Entry point: {self.db.entry_point:04X}\n\n")
                
                if not hasattr(self.db, 'memory') or not self.db.memory:
                    logger.info("ASM generation skipped: memory is empty.")
                    return

                sorted_addrs = sorted(self.db.memory.keys())
                start_addr = sorted_addrs[0]
                end_addr = sorted_addrs[-1]
                
                mem_bytes = bytearray()
                for i in range(start_addr, end_addr + 1):
                    info = self.db.memory.get(i)
                    mem_bytes.append(info.byte_value if info else 0)

                for inst in self.md.disasm(bytes(mem_bytes), start_addr):
                    addr = inst.address
                    label = self.db.get_label_at(addr)
                    
                    if label:
                        f.write(f"{label}:\n")

                    # Replace numeric operands with labels where available
                    op_str = inst.op_str
                    for op in inst.operands:
                        if op.type == x86_const.X86_OP_IMM:
                            target_label = self.db.get_label_at(op.imm)
                            if target_label:
                                # Use replace for simplicity; a more robust solution
                                # would reformat the whole operand string.
                                op_str = op_str.replace(hex(op.imm), target_label)
                    
                    f.write(f"\t{inst.mnemonic}\t{op_str}\n")
                
                logger.info(f"ASM generated: {path}")
        except Exception as e:
            logger.error(f"Error generating ASM: {e}")
