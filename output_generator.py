import logging
from database import AnalysisDatabase

def generate_outputs(db_result, mz_filename):
    """
    Generate .lst and .asm files from the analysis database.
    """
    # Ensure db_result is an AnalysisDatabase instance
    if not isinstance(db_result, AnalysisDatabase):
        raise ValueError("Invalid database result for output generation.")
    
    # Generate .lst file
    lst_path = mz_filename.replace('.exe', '.lst')
    with open(lst_path, 'w') as f:
        f.write("# LST Output\n")
        if db_result.functions:
            for func in db_result.functions.values():  # Use .values() for dict
                end_hex = hex(func.end_addr) if func.end_addr is not None else "(end unknown)"
                f.write(f"func {hex(func.start_addr)} {end_hex} - {func.name}\n")
                disasm_lines = getattr(func, 'disassembly', [])
                if not disasm_lines:
                    # Fallback: Basic hex dump for function range
                    end_limit = func.end_addr if func.end_addr is not None else func.start_addr + 32
                    for addr in range(func.start_addr, min(end_limit, func.start_addr + 32)):  # Limit to 32 bytes
                        info = db_result.get_address_info(addr)
                        if info and info.byte_value is not None:
                            f.write(f"{hex(addr)}: {info.byte_value:02x}\n")
                else:
                    for line in disasm_lines:
                        f.write(f"{line}\n")
        else:
            # Global fallback if no functions
            f.write("No functions detected.\n")
            for addr, info in list(db_result.memory.items())[:20]:  # First 20 bytes
                if info.byte_value is not None:
                    f.write(f"{hex(addr)}: {info.byte_value:02x}\n")
    
    # Generate .asm file
    asm_path = mz_filename.replace('.exe', '.asm')
    with open(asm_path, 'w') as f:
        f.write("# ASM Output\n")
        if db_result.functions:
            for func in db_result.functions.values():
                f.write(f"{func.name} proc\n")
                # Use disassembly as proxy for assembly; format simply
                disasm_lines = getattr(func, 'disassembly', [])
                if not disasm_lines:
                    # Fallback hex/byte asm
                    end_limit = func.end_addr if func.end_addr is not None else func.start_addr + 32
                    for addr in range(func.start_addr, min(end_limit, func.start_addr + 32)):
                        info = db_result.get_address_info(addr)
                        if info and info.byte_value is not None:
                            f.write(f"    db {info.byte_value:02x}h  ; {hex(addr)}\n")
                else:
                    for line in disasm_lines:
                        # Simple asm format: strip hex prefix if present
                        asm_line = line.replace(hex(func.start_addr), func.name, 1)  # Label first
                        f.write(f"    {asm_line}\n")
                f.write(f"{func.name} endp\n")
        else:
            # Global fallback
            f.write("No functions; raw bytes:\n")
            for addr, info in list(db_result.memory.items())[:20]:
                if info.byte_value is not None:
                    f.write(f"    db {info.byte_value:02x}h  ; {hex(addr)}\n")
    
    print(f"Generated .lst and .asm files successfully: {lst_path}, {asm_path}")
    # Log summary
    func_count = len(db_result.functions)
    print(f"Output summary: {func_count} functions, {sum(len(getattr(f, 'disassembly', [])) for f in db_result.functions.values())} disasm lines")
