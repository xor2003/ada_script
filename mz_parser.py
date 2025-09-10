"""
mz_parser.py: Handles the loading and parsing of DOS MZ-EXE files.
Performs initial static analysis on the relocation table.
"""

import pefile
from database import AnalysisDatabase, AddressInfo, Segment, ITEM_TYPE_DATA, DATA_TYPE_WORD

def load_mz_exe(filepath: str, db: AnalysisDatabase) -> bool:
    """
    Parses an MZ-EXE file, populates the database with its memory image,
    and uses relocation info to identify an initial data segment.
    """
    print(f"[*] Loading MZ-EXE file: {filepath}")
    try:
        pe = pefile.PE(filepath, fast_load=True)
    except pefile.PEFormatError as e:
        print(f"[!] Error: Not a valid PE or MZ file. {e}")
        return False

    if not hasattr(pe, 'DOS_HEADER') or pe.DOS_HEADER.e_magic != 0x5A4D:
        print("[!] Error: MZ magic number not found.")
        return False

    dos_header = pe.DOS_HEADER
    
    header_paragraphs = dos_header.e_cparhdr
    header_size = header_paragraphs * 16
    
    file_size_pages = dos_header.e_cp
    last_page_bytes = dos_header.e_cblp
    
    if last_page_bytes == 0 and file_size_pages > 0:
        image_size = (file_size_pages - 1) * 512 + 512
    else:
        image_size = (file_size_pages - 1) * 512 + last_page_bytes
        
    load_module_size = image_size - header_size
    load_segment_base = 0x1000 # A typical segment for the PSP

    entry_cs = dos_header.e_cs + load_segment_base
    entry_ip = dos_header.e_ip
    db.entry_point = db.to_linear_address(entry_cs, entry_ip)
    print(f"[*] Entry Point: {entry_cs:04X}:{entry_ip:04X} (Linear: {db.entry_point:05X})")

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
    print(f"[*] Created initial CODE segment 'cseg' at {code_seg_selector:04X}")

    image_data = pe.get_data(header_size, load_module_size)
    for i, byte in enumerate(image_data):
        addr = code_seg_start + i
        db.memory[addr] = AddressInfo(address=addr, byte_value=byte)

    relocated_data_targets = set()
    if hasattr(pe, 'relocations'):
        print(f"[*] Processing {len(pe.relocations)} relocation entries...")
        for reloc in pe.relocations:
            reloc_addr_in_mem = db.to_linear_address(reloc.segment + load_segment_base, reloc.offset)

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
                print(f"[!] Warning: Relocation address {reloc_addr_in_mem:05X} is out of bounds.")

    # Heuristically create a data segment from relocation targets
    if relocated_data_targets:
        min_data = min(relocated_data_targets)
        max_data = max(relocated_data_targets)
        
        # Ensure the data segment doesn't overlap with the code segment
        if min_data < code_seg_end:
            print("[!] Warning: Relocated data appears to overlap with code segment. Skipping dseg creation.")
        else:
            dseg_selector = min_data >> 4
            db.segments.append(Segment(
                name="dseg",
                start_addr=db.to_linear_address(dseg_selector, 0),
                end_addr=max_data + 256, # Add padding
                selector=dseg_selector,
                seg_class="DATA"
            ))
            print(f"[*] Heuristically created DATA segment 'dseg' at {dseg_selector:04X}")

            # Mark and name the relocation targets as data variables
            for addr in sorted(list(relocated_data_targets)):
                info = db.get_address_info(addr)
                if info:
                    info.item_type = ITEM_TYPE_DATA
                    info.data_type = DATA_TYPE_WORD
                    if not info.label:
                        info.label = f"word_{addr:X}"

    return True
