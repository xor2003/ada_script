"""
MZ Parser Module
Enhanced with pefile for DOS MZ/PE parsing.
"""

import os
import pefile
from database import Segment

def parse_mz_file(filename):
    """
    Parse an MZ (Microsoft executable) file, handling pure DOS MZ and PE.
    :param filename: Path to MZ file (e.g., egame.exe)
    :return: Dict with raw_bytes, entry_point, segments
    """
    if not os.path.exists(filename):
        raise FileNotFoundError(f"MZ file not found: {filename}")
    
    try:
        with open(filename, 'rb') as f:
            raw_bytes = f.read()
        
        # Parse DOS/MZ header using struct - key fields only
        import struct
        if len(raw_bytes) < 64:
            raise ValueError("File too short for MZ header")
        
        e_magic = struct.unpack_from('<2s', raw_bytes, 0)[0]
        if e_magic != b'MZ':
            raise ValueError("Not a valid MZ executable")
        
        e_ip = struct.unpack_from('<H', raw_bytes, 20)[0]
        e_cs = struct.unpack_from('<H', raw_bytes, 22)[0]
        e_lfanew = struct.unpack_from('<I', raw_bytes, 60)[0]
        
        print(f"[DEBUG] Parsing MZ file: {filename} (DOS header valid: e_ip=0x{e_ip:x}, e_cs=0x{e_cs:x}, e_lfanew=0x{e_lfanew:x})")
        
        # Check if PE (Windows) or pure MZ (DOS)
        is_pe = False
        entry_point = 0
        segments = []
        
        if 0 < e_lfanew < len(raw_bytes) - 3 and raw_bytes[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
            is_pe = True
            try:
                pe = pefile.PE(data=raw_bytes)
                entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                for sect in pe.sections:
                    start = sect.VirtualAddress
                    size = sect.Misc_VirtualSize or sect.SizeOfRawData
                    name = sect.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                    seg_class = 'CODE' if any(kw in name.lower() for kw in ['code', 'text', 'exec']) else 'DATA'
                    segments.append(Segment(name or 'unknown', start, start + size, 0, seg_class))
                print(f"[DEBUG] Detected PE format with {len(segments)} sections")
            except Exception as pe_err:
                print(f"[DEBUG] PE parse failed, falling back to MZ: {pe_err}")
                is_pe = False
        else:
            # Pure MZ/DOS: Entry = (CS << 4) + IP; flat segment
            entry_point = (e_cs << 4) + e_ip
            segments = [Segment('code', 0, len(raw_bytes), e_cs, 'CODE')]
            print(f"[DEBUG] Detected pure MZ/DOS format")
        
        if not segments:
            segments = [Segment('code', 0, len(raw_bytes), e_cs, 'CODE')]
        
        mz_data = {
            'raw_bytes': raw_bytes,
            'entry_point': entry_point,
            'segments': segments,
            'is_pe': is_pe
        }
        print(f"[DEBUG] MZ parsed: {len(raw_bytes)} bytes, entry=0x{entry_point:x}, {len(segments)} segments")
        return mz_data
    except Exception as e:
        raise RuntimeError(f"Failed to parse MZ: {e}")