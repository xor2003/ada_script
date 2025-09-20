import logging
from database import ITEM_TYPE_CODE, AnalysisDatabase, AddressInfo
from idc_engine import IDCScript

logger = logging.getLogger(__name__)

class EmulationAnalyzer:
    def __init__(self, db):
        self.db = db
        # Existing initialization if any
        logger.info("EmulationAnalyzer initialized with database")

    def analyze(self):
        # Basic emulation analysis with function detection
        from capstone import Cs, CS_ARCH_X86, CS_MODE_16  # For DOS 16-bit
        md = Cs(CS_ARCH_X86, CS_MODE_16)
        
        entry = self.db.entry_point
        if not entry:
            logger.warning("No entry point; skipping analysis")
            return
        
        # Mark entry as code
        self.db.set_item_type(entry, ITEM_TYPE_CODE)
        
        # Bulk fetch bytes for efficient disassembly
        max_scan = entry + 0x10000
        all_bytes = self._get_bytes_at(entry, max_scan - entry)
        if not all_bytes:
            logger.warning("No bytes to analyze")
            return
        
        logger.debug(f"Disassembling {len(all_bytes)} bytes from {hex(entry)}")
        instructions = list(md.disasm(all_bytes, entry))
        logger.debug(f"Generated {len(instructions)} instructions")
        
        # Store instructions in DB for output generation
        for instr in instructions:
            addr = instr.address
            info = self.db.get_address_info(addr)
            if info:
                info.instruction = instr
                info.item_type = ITEM_TYPE_CODE
                # Add to function disassembly if in func (init if needed)
                func = self.db.get_function_containing(addr)
                if func:
                    if not hasattr(func, 'disassembly'):
                        func.disassembly = []
                    func.disassembly.append(f"{hex(addr)}: {instr.mnemonic} {instr.op_str}")
        
        # Enhanced function detection: scan for multiple prologue patterns
        i = 0
        while i < len(instructions):
            instr = instructions[i]
            # Pattern 1: PUSH BP; MOV BP, SP
            if instr.mnemonic == 'push' and instr.op_str == 'bp' and i+1 < len(instructions):
                next_instr = instructions[i+1]
                if next_instr.mnemonic == 'mov' and next_instr.op_str == 'bp,sp':
                    func_start = instr.address
                    func_end = self._find_ret_in_instructions(instructions, i+2)
                    if func_end:
                        self.db.add_function(func_start, func_end)
                        logger.debug(f"Detected function (PUSH BP; MOV BP,SP) at {hex(func_start)} to {hex(func_end)}")
                        i = next((j for j in range(i+2, len(instructions)) if instructions[j].address >= func_end), len(instructions))
                        continue
            
            # Pattern 2: ENTER (used in some compilers)
            elif instr.mnemonic == 'enter':
                func_start = instr.address
                func_end = self._find_ret_in_instructions(instructions, i+1)
                if func_end:
                    self.db.add_function(func_start, func_end)
                    logger.debug(f"Detected function (ENTER) at {hex(func_start)} to {hex(func_end)}")
                    i = next((j for j in range(i+1, len(instructions)) if instructions[j].address >= func_end), len(instructions))
                    continue
            
            # Pattern 3: CALL target (function might be called before being defined)
            elif instr.mnemonic == 'call':
                target_addr = self._parse_call_target(instr.op_str)
                if target_addr and not self.db.get_function_at(target_addr):
                    # Mark target as function start
                    self.db.add_function(target_addr, None)
                    logger.debug(f"Detected function via CALL at {hex(target_addr)}")
            
            i += 1
        
        logger.info("Emulation analysis completed")
    
    def _get_bytes_at(self, addr, size):
        """Fetch bytes from DB memory."""
        bytes_list = []
        for i in range(size):
            info = self.db.get_address_info(addr + i)
            if info and hasattr(info, 'byte_value'):
                bytes_list.append(info.byte_value)
            else:
                break
        return bytes(bytes_list)
    
    def _find_ret_in_instructions(self, instructions, start_idx):
        """Find return instruction in instruction list (ret, iret, retf)."""
        for j in range(start_idx, len(instructions)):
            instr = instructions[j]
            if instr.mnemonic in ['ret', 'iret', 'retf']:
                logger.debug(f"Found return {instr.mnemonic} at {hex(instr.address)}")
                return instr.address + instr.size
        return None

    def _parse_call_target(self, op_str):
        """Parse call target address from operand string."""
        # Handle direct calls: call 1234
        if op_str.startswith('0x'):
            try:
                return int(op_str, 16)
            except ValueError:
                pass
        # Handle relative calls: call -123
        elif op_str.startswith('-') or op_str.startswith('+'):
            try:
                return int(op_str, 10)
            except ValueError:
                pass
        # Handle register-based calls: call [bx]
        # We'll skip these for now
        return None

    def _find_ret(self, start):
        """Fallback: Disasm scan for RET variants in bytes."""
        search_size = 0x1000
        search_bytes = self._get_bytes_at(start, search_size)
        if not search_bytes:
            return None
        from capstone import Cs, CS_ARCH_X86, CS_MODE_16
        md = Cs(CS_ARCH_X86, CS_MODE_16)
        for i in md.disasm(search_bytes, start):
            if i.mnemonic in ['ret', 'iret', 'retf']:
                logger.debug(f"Fallback: Found return {i.mnemonic} at {hex(i.address)}")
                return i.address + i.size
        return None

    def is_data_region(self, addr):
        # Check if addr falls in data segments (from MZ parser)
        for seg in self.db.segments:
            if seg.start_addr <= addr < seg.end_addr and seg.seg_class == "DATA":
                return True
        return False

    def classify_region(self, start_addr, size):
        if self.is_data_region(start_addr):  # Use MZ flags/parser data
            return "DATA"
        return "CODE"

    # Rest of the class remains unchanged
    def other_methods(self):
        pass


def emulate(script: IDCScript, mz_data: dict) -> AnalysisDatabase:
    """
    Main emulation entry: Load MZ into DB, apply IDC basics, analyze.
    :param script: Parsed IDCScript
    :param mz_data: Dict from mz_parser
    :return: Populated AnalysisDatabase
    """
    logger.info(f"Starting emulation with script ({len(script.variables) if script else 0} vars, {len(script.functions) if script else 0} funcs) and MZ data")
    
    db = AnalysisDatabase()
    raw_bytes = mz_data['raw_bytes']
    
    # Populate memory with raw bytes (assume CODE for simplicity)
    for i, b in enumerate(raw_bytes):
        db.memory[i] = AddressInfo(i, b, ITEM_TYPE_CODE)
    
    db.entry_point = mz_data['entry_point']
    db.segments = mz_data['segments']
    db.file_format = "MZ"
    
    # Stub IDC application: Set labels for variables (dummy addresses based on entry)
    if script:
        base_addr = db.entry_point or 0x1000
        for var in script.variables:
            dummy_addr = base_addr + (hash(var.get('name', '')) % 0x1000)
            db.set_label(dummy_addr, var['name'])
            logger.debug(f"Applied IDC var label: {var['name']} at 0x{dummy_addr:x}")
        
        # Add script functions as DB functions (dummy ends)
        for func_def in script.functions:
            func_name = func_def.get('name', 'unknown')
            func_start = base_addr + (hash(func_name) % 0x1000)
            db.add_function(func_start, func_start + 0x100)  # Dummy size
            logger.debug(f"Applied IDC func: {func_name} at 0x{func_start:x}")
    
    # Run static analysis (no full emulation for safety)
    analyzer = EmulationAnalyzer(db)
    analyzer.analyze()
    
    logger.info("Emulation/analysis completed successfully")
    return db