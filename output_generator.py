import logging
import os

logger = logging.getLogger(__name__)

class LSTGenerator:
    def __init__(self, db):
        self.db = db

    def generate(self, path):
        try:
            with open(path, 'w') as f:
                f.write("Ada Script LST Output\n")
                f.write("===================\n\n")
                if hasattr(self.db, 'segments') and self.db.segments:
                    for seg in self.db.segments:
                        f.write(f"Segment {seg.name}: {seg.start_addr:04X} - {seg.end_addr - seg.start_addr:04X} bytes\n")
                if hasattr(self.db, 'memory') and self.db.memory:
                    for addr, info in sorted(self.db.memory.items()):
                        if hasattr(info, 'byte_value'):
                            f.write(f"{addr:04X}: {info.byte_value:02X}\n")
                logger.info(f"LST generated: {path}")
        except Exception as e:
            logger.error(f"Error generating LST: {e}")

class ASMGenerator:
    def __init__(self, db):
        self.db = db
        from idc_engine import IDCEngine  # Import here to avoid circular
        self.decoder = IDCEngine()

    def generate(self, path):
        try:
            with open(path, 'w') as f:
                f.write("Ada Script ASM Output\n")
                f.write("====================\n\n")
                if hasattr(self.db, 'entry_point'):
                    f.write(f"Entry point: {self.db.entry_point:04X}\n\n")
                if hasattr(self.db, 'memory') and self.db.memory:
                    addr = 0
                    while addr in self.db.memory:
                        info = self.db.memory[addr]
                        if hasattr(info, 'byte_value'):
                            bytes_data = bytes([info.byte_value])
                            # Fetch next bytes if needed (simple single-byte)
                            inst = self.decoder.decode_instruction(bytes_data, addr)
                            if inst and 'mnemonic' in inst:
                                f.write(f"{inst['addr']}: {inst['mnemonic']}\n")
                            else:
                                f.write(f"{addr:04X}: db {info.byte_value:02X}\n")
                            addr += 1
                        else:
                            break
                logger.info(f"ASM generated: {path}")
        except Exception as e:
            logger.error(f"Error generating ASM: {e}")
