"""
database.py: The central data store for the disassembly analysis.
"""

import collections
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

# Item types classify what each byte in memory represents
ITEM_TYPE_UNDEFINED = "UNDEFINED"
ITEM_TYPE_CODE = "CODE"
ITEM_TYPE_DATA = "DATA"

# Data types for more specific formatting
DATA_TYPE_BYTE = 1
DATA_TYPE_WORD = 2
DATA_TYPE_DWORD = 4
DATA_TYPE_ASCII = 10

@dataclass
class AddressInfo:
    """Holds all information about a single address in memory."""
    address: int
    byte_value: int
    item_type: str = ITEM_TYPE_UNDEFINED
    item_size: int = 1
    data_type: int = DATA_TYPE_BYTE
    label: Optional[str] = None
    comment: Optional[str] = None
    repeatable_comment: Optional[str] = None
    instruction: Optional[Any] = None  # capstone.CsInsn
    xrefs_to: List[int] = field(default_factory=list)
    xrefs_from: List[int] = field(default_factory=list)
    relocation: bool = False

@dataclass
class Segment:
    """Represents a memory segment."""
    name: str
    start_addr: int
    end_addr: int
    selector: int
    seg_class: str = "CODE"
    is_32bit: bool = False

@dataclass
class Function:
    """Represents a function with its properties."""
    start_addr: int
    end_addr: int
    name: str
    frame_size: int = 0
    local_vars: Dict[int, Tuple[str, int]] = field(default_factory=dict) # offset -> (name, size)

@dataclass
class OperandFormat:
    """Stores formatting overrides for an instruction operand."""
    format_type: str # e.g., 'hex', 'dec', 'offset', 'enum'
    value: Any = None # e.g., enum_id for 'enum', base for 'offset'

class AnalysisDatabase:
    """The main container class for all disassembly information."""

    def __init__(self):
        self.memory: Dict[int, AddressInfo] = {}
        self.segments: List[Segment] = []
        self.functions: Dict[int, Function] = {} # start_addr -> Function
        self.entry_point: int = 0
        self.operand_format_overrides: Dict[Tuple[int, int], OperandFormat] = {} # (addr, op_idx) -> Format
        self.segment_register_assumptions: Dict[int, Dict[str, int]] = collections.defaultdict(dict) # addr -> {'cs': val, 'ds': val}

    def get_address_info(self, address: int) -> Optional[AddressInfo]:
        """Safely retrieves AddressInfo for a given linear address."""
        return self.memory.get(address)

    def get_label_at(self, address: int) -> Optional[str]:
        """Returns the label for an address, if one exists."""
        info = self.get_address_info(address)
        return info.label if info else None

    def to_segment_offset(self, linear_address: int) -> Optional[Tuple[str, int]]:
        """Converts a linear address to a (segment_name, offset) pair."""
        for seg in self.segments:
            if seg.start_addr <= linear_address < seg.end_addr:
                return (seg.name, linear_address - seg.start_addr)
        return None

    def to_linear_address(self, seg_selector: int, offset: int) -> int:
        """Converts a 16-bit segment:offset pair to a linear address."""
        return (seg_selector << 4) + offset

    def get_segment_by_selector(self, selector: int) -> Optional[Segment]:
        """Finds a segment by its selector value."""
        for seg in self.segments:
            if seg.selector == selector:
                return seg
        return None

    def get_function_containing(self, address: int) -> Optional[Function]:
        """Finds the function that contains the given address."""
        for func in self.functions.values():
            if func.start_addr <= address < func.end_addr:
                return func
        return None

    def add_function(self, start_addr: int, end_addr: int):
        """Adds or updates a function in the database."""
        if start_addr in self.functions:
            # Update existing function if new end is larger
            self.functions[start_addr].end_addr = max(self.functions[start_addr].end_addr, end_addr)
        else:
            name = self.get_label_at(start_addr) or f"sub_{start_addr:X}"
            self.functions[start_addr] = Function(start_addr, end_addr, name)
            # Ensure the start address has a label
            info = self.get_address_info(start_addr)
            if info and not info.label:
                info.label = name
