"""
mz_parser.py: Handles the loading and parsing of DOS MZ-EXE files.
Performs initial static analysis on the relocation table.
"""

import struct
import logging
from database import AnalysisDatabase, AddressInfo, Segment

logger = logging.getLogger(__name__)

def load_mz_exe(filepath: str, db: AnalysisDatabase) -> bool:
    """
    Parses an MZ-EXE file, populates the database with its memory image,
    and uses relocation info to identify an initial data segment.
    """
    logger.info(f"Loading MZ-EXE file: {filepath}")
    db.file_format = "MZ"
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return False

    if len(data) < 2 or data[0:2] != b'MZ':
        logger.error("MZ magic number not found.")
        return False

    e_cblp = struct.unpack('<H', data[2:4])[0]
    e_cp = struct.unpack('<H', data[4:6])[0]
    e_crlc = struct.unpack('<H', data[6:8])[0]
    e_cparhdr = struct.unpack('<H', data[8:10])[0]
    e_ss = struct.unpack('<H', data[14:16])[0]
    e_sp = struct.unpack('<H', data[16:18])[0]
    e_ip = struct.unpack('<H', data[20:22])[0]
    e_cs = struct.unpack('<H', data[22:24])[0]
    e_lfarlc = struct.unpack('<H', data[24:26])[0]
    
    logger.debug(f"MZ Header: Bytes in last page={e_cblp}, Pages={e_cp}, Relocs={e_crlc}, Header paras={e_cparhdr}, Reloc offset={e_lfarlc:04X}")
    
    header_size = e_cparhdr * 16
    
    if e_cblp == 0:
        image_size = e_cp * 512
    else:
        image_size = (e_cp - 1) * 512 + e_cblp
        
    load_module_size = image_size - header_size
    # The load segment base for an EXE is typically where the PSP ends.
    # 0x100 is a safe assumption for the PSP size, so the code starts at segment 0x1000.
    load_segment_base = 0x1000

    # Store initial register values, adjusted by the load base segment
    db.initial_cs = e_cs + load_segment_base
    db.initial_ip = e_ip
    db.initial_ss = e_ss + load_segment_base
    db.initial_sp = e_sp
    db.entry_point = db.to_linear_address(db.initial_cs, db.initial_ip)
    
    logger.info(f"Entry Point: {db.initial_cs:04X}:{db.initial_ip:04X} (Linear: {db.entry_point:05X})")
    logger.info(f"Initial Stack: {db.initial_ss:04X}:{db.initial_sp:04X}")

    code_seg_start = db.to_linear_address(load_segment_base, 0)
    code_seg_end = code_seg_start + load_module_size
    db.segments.append(Segment(
        name="cseg",
        start_addr=code_seg_start,
        end_addr=code_seg_end,
        selector=load_segment_base,
        seg_class="CODE"
    ))
    logger.info(f"Created initial CODE segment 'cseg' at {load_segment_base:04X}")

    image_data = data[header_size:header_size+load_module_size]
    logger.debug(f"Loading {len(image_data)} bytes into memory at {code_seg_start:05X}")
    for i, byte in enumerate(image_data):
        addr = code_seg_start + i
        db.memory[addr] = AddressInfo(address=addr, byte_value=byte)

    relocated_data_targets = set()
    if e_crlc > 0 and e_lfarlc > 0:
        logger.info(f"Processing {e_crlc} relocation entries...")
        reloc_table = data[e_lfarlc:e_lfarlc + e_crlc*4]
        
        processed_relocs = 0
        for i in range(e_crlc):
            offset = i*4
            reloc_offset = struct.unpack('<H', reloc_table[offset:offset+2])[0]
            reloc_segment = struct.unpack('<H', reloc_table[offset+2:offset+4])[0]
            
            reloc_addr_in_mem = db.to_linear_address(reloc_segment + load_segment_base, reloc_offset)
            
            if reloc_addr_in_mem in db.memory and (reloc_addr_in_mem + 1) in db.memory:
                low_byte = db.memory[reloc_addr_in_mem].byte_value
                high_byte = db.memory[reloc_addr_in_mem + 1].byte_value
                original_val = (high_byte << 8) | low_byte
                
                new_val = original_val + load_segment_base
                
                db.memory[reloc_addr_in_mem].byte_value = new_val & 0xFF
                db.memory[reloc_addr_in_mem + 1].byte_value = (new_val >> 8) & 0xFF
                db.memory[reloc_addr_in_mem].relocation = True
                db.memory[reloc_addr_in_mem + 1].relocation = True
                data_target_addr = db.to_linear_address(new_val, 0)
                relocated_data_targets.add(data_target_addr)
                if i % 50 == 0:  # Sample every 50 for large files
                    logger.debug(f"Processed reloc #{i}: offset={reloc_offset:04X}, target={data_target_addr:05X}")
                processed_relocs += 1
            else:
                logger.warning(f"Relocation address {reloc_addr_in_mem:05X} is out of bounds.")
        logger.debug(f"Applied {processed_relocs}/{e_crlc} relocations; {len(relocated_data_targets)} unique data targets")

    if relocated_data_targets:
        min_data = min(relocated_data_targets)
        max_data = max(relocated_data_targets)
        if min_data >= code_seg_end:
            dseg_selector = min_data >> 4
            db.segments.append(Segment(
                name="dseg",
                start_addr=db.to_linear_address(dseg_selector, 0),
                end_addr=max_data + 256,
                selector=dseg_selector,
                seg_class="DATA"
            ))
            logger.info(f"Heuristically created DATA segment 'dseg' at {dseg_selector:04X}")

    return True