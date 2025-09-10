"""
mz_parser.py: Handles the loading and parsing of DOS MZ-EXE files.
Performs initial static analysis on the relocation table.
"""

import struct
import logging
from database import AnalysisDatabase, AddressInfo, Segment, ITEM_TYPE_DATA, DATA_TYPE_WORD

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

    # Check MZ signature
    if len(data) < 2 or data[0:2] != b'MZ':
        logger.error("MZ magic number not found.")
        return False

    # Parse DOS header fields
    e_cblp = struct.unpack('<H', data[2:4])[0]
    e_cp = struct.unpack('<H', data[4:6])[0]
    e_crlc = struct.unpack('<H', data[6:8])[0]  # Relocation count
    e_cparhdr = struct.unpack('<H', data[8:10])[0]  # Header size in paragraphs
    e_minalloc = struct.unpack('<H', data[10:12])[0]
    e_maxalloc = struct.unpack('<H', data[12:14])[0]
    e_ss = struct.unpack('<H', data[14:16])[0]
    e_sp = struct.unpack('<H', data[16:18])[0]
    e_ip = struct.unpack('<H', data[20:22])[0]
    e_cs = struct.unpack('<H', data[22:24])[0]
    e_lfarlc = struct.unpack('<H', data[24:26])[0]  # Relocation table offset
    
    header_size = e_cparhdr * 16
    
    # Calculate image size
    if e_cblp == 0:
        image_size = e_cp * 512
    else:
        image_size = (e_cp - 1) * 512 + e_cblp
        
    load_module_size = image_size - header_size
    load_segment_base = 0x1000  # Typical segment for PSP

    entry_cs = e_cs + load_segment_base
    db.entry_point = db.to_linear_address(entry_cs, e_ip)
    logger.info(f"Entry Point: {entry_cs:04X}:{e_ip:04X} (Linear: {db.entry_point:05X})")

    code_seg_selector = entry_cs
    code_seg_start = db.to_linear_address(code_seg_selector, 0)
    code_seg_end = code_seg_start + load_module_size
    db.segments.append(Segment(
        name="cseg",
        start_addr=code_seg_start,
        end_addr=code_seg_end,
        selector=code_seg_selector,
        seg_class="CODE"
    ))
    logger.info(f"Created initial CODE segment 'cseg' at {code_seg_selector:04X}")

    # Copy image data to memory
    image_data = data[header_size:header_size+load_module_size]
    for i, byte in enumerate(image_data):
        addr = code_seg_start + i
        db.memory[addr] = AddressInfo(address=addr, byte_value=byte)

    # Process relocation table
    relocated_data_targets = set()
    if e_crlc > 0 and e_lfarlc > 0:
        logger.info(f"Processing {e_crlc} relocation entries...")
        reloc_table = data[e_lfarlc:e_lfarlc + e_crlc*4]
        
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

                # The target of the relocation is likely data
                data_target_addr = db.to_linear_address(new_val, 0)
                relocated_data_targets.add(data_target_addr)
            else:
                logger.warning(f"Relocation address {reloc_addr_in_mem:05X} is out of bounds.")

    # Heuristically create a data segment from relocation targets
    if relocated_data_targets:
        min_data = min(relocated_data_targets)
        max_data = max(relocated_data_targets)

        # Check if relocated data is within the code segment
        if min_data < code_seg_end:
            # Check if all relocated data is within the code segment
            if max_data < code_seg_end:
                logger.info("Relocated data is entirely within the code segment. Marking as data within code.")
                # Mark and name the relocation targets as data variables within the code segment
                for addr in sorted(list(relocated_data_targets)):
                    info = db.get_address_info(addr)
                    if info:
                        info.item_type = ITEM_TYPE_DATA
                        info.data_type = DATA_TYPE_WORD
                        if not info.label:
                            info.label = f"word_{addr:X}"
            else:
                # Some relocated data is outside the code segment
                logger.warning("Relocated data overlaps with code segment. Creating separate data segment.")
                # Adjust min_data to start after the code segment
                min_data = code_seg_end

                dseg_selector = min_data >> 4
                db.segments.append(Segment(
                    name="dseg",
                    start_addr=db.to_linear_address(dseg_selector, 0),
                    end_addr=max_data + 256,  # Add padding
                    selector=dseg_selector,
                    seg_class="DATA"
                ))
                logger.info(f"Heuristically created DATA segment 'dseg' at {dseg_selector:04X}")

                # Mark and name the relocation targets as data variables
                for addr in sorted(list(relocated_data_targets)):
                    info = db.get_address_info(addr)
                    if info:
                        info.item_type = ITEM_TYPE_DATA
                        info.data_type = DATA_TYPE_WORD
                        if not info.label:
                            info.label = f"word_{addr:X}"
        else:
            # All relocated data is outside the code segment
            logger.info("Relocated data does not overlap with code segment.")
            dseg_selector = min_data >> 4
            db.segments.append(Segment(
                name="dseg",
                start_addr=db.to_linear_address(dseg_selector, 0),
                end_addr=max_data + 256,  # Add padding
                selector=dseg_selector,
                seg_class="DATA"
            ))
            logger.info(f"Heuristically created DATA segment 'dseg' at {dseg_selector:04X}")

            # Mark and name the relocation targets as data variables
            for addr in sorted(list(relocated_data_targets)):
                info = db.get_address_info(addr)
                if info:
                    info.item_type = ITEM_TYPE_DATA
                    info.data_type = DATA_TYPE_WORD
                    if not info.label:
                        info.label = f"word_{addr:X}"

    return True
