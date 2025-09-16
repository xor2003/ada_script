"""
idc_engine.py: Simplified IDC script parser that focuses on function calls
"""
import logging
import re
from database import (
    AnalysisDatabase, ITEM_TYPE_CODE, ITEM_TYPE_DATA, DATA_TYPE_ASCII,
    DATA_TYPE_BYTE, DATA_TYPE_WORD, DATA_TYPE_DWORD,
    Segment, OperandFormat
)

logger = logging.getLogger(__name__)

class IDCScriptEngine:
    def __init__(self, db: AnalysisDatabase):
        self.db = db
        self.function_map = self._initialize_function_map()
        # Regex to match IDC function calls with arguments
        self.func_regex = re.compile(
            r'(\w+)\s*\(\s*([^;]*?)\s*\)\s*;',
            re.DOTALL
        )
        # Regex to split arguments while handling strings
        self.arg_split_regex = re.compile(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)')

    def _initialize_function_map(self):
        return {
            "create_insn": self.idc_create_insn,
            "create_byte": lambda a: self.idc_create_data(a, 1),
            "create_word": lambda a: self.idc_create_data(a, 2),
            "create_dword": lambda a: self.idc_create_data(a, 4),
            "create_strlit": self.idc_create_ascii,
            "set_name": self.idc_set_name,
            "set_cmt": self.idc_set_cmt,
            "add_func": self.idc_add_func,
            "op_hex": lambda a, n: self.idc_op_format(a, n, 'hex'),
            "op_dec": lambda a, n: self.idc_op_format(a, n, 'dec'),
            "op_offset": self.idc_op_offset,
            "op_plain_offset": self.idc_op_offset,
            "add_segm_ex": self.idc_add_segm_ex,
            **{k: self.idc_no_op for k in [
                "update_extra_cmt", "set_frame_size", "define_local_var", "op_enum",
                "op_stroff", "op_stkvar", "op_seg", "SegRename", "SegClass", 
                "SegDefReg", "set_segm_type", "split_sreg_range", "delete_all_segments",
                "add_enum", "add_enum_member", "add_struc", "add_struc_member",
                "get_struc_id", "get_member_id", "SetType", "set_struc_align",
                "set_processor_type", "set_inf_attr", "set_flag", "add_default_til",
                "begin_type_updating", "end_type_updating", "make_array", "get_inf_attr", "GetEnum"
            ]}
        }

    def idc_no_op(self, *args, **kwargs): 
        return 0
        
    def idc_create_insn(self, addr):
        if not isinstance(addr, int): return
        if info := self.db.get_address_info(addr): 
            info.item_type = ITEM_TYPE_CODE
            
    def idc_create_data(self, addr, size):
        if not isinstance(addr, int): return
        for i in range(size):
            if info := self.db.get_address_info(addr + i):
                info.item_type = ITEM_TYPE_DATA
                if i == 0:
                    info.item_size = size
                    if size == 4: info.data_type = DATA_TYPE_DWORD
                    elif size == 2: info.data_type = DATA_TYPE_WORD
                    elif size == 1: info.data_type = DATA_TYPE_BYTE
                    
    def idc_create_ascii(self, addr, length=0):
        if not isinstance(addr, int): return
        if length == 0:
            curr_addr, length = addr, 0
            while True:
                info = self.db.get_address_info(curr_addr)
                if not info: break
                # Count this byte even if it's null
                length += 1
                if info.byte_value == 0: break
                curr_addr += 1
        if info := self.db.get_address_info(addr):
            info.item_type = ITEM_TYPE_DATA
            info.item_size = length
            info.data_type = DATA_TYPE_ASCII
            
    def idc_set_name(self, addr, name, *args):
        if not isinstance(addr, int): return
        if info := self.db.get_address_info(addr): 
            info.label = name
            
    def idc_set_cmt(self, addr, comment, repeatable=0, *args):
        if not isinstance(addr, int): return
        is_repeatable = bool(int(repeatable)) if str(repeatable).isdigit() else False
        if info := self.db.get_address_info(addr):
            if is_repeatable: 
                info.repeatable_comment = comment
            else: 
                info.comment = comment
                
    def idc_op_format(self, addr, op_index, fmt_type):
        if not isinstance(addr, int): return
        self.db.operand_format_overrides[(addr, op_index)] = OperandFormat(fmt_type)
        
    def idc_op_offset(self, addr, op_index, base):
        if not isinstance(addr, int): return
        self.db.operand_format_overrides[(addr, op_index)] = OperandFormat('offset', base)
        
    def idc_add_func(self, start_addr, end_addr):
        if not isinstance(start_addr, int) or not isinstance(end_addr, int): return
        self.db.add_function(start_addr, end_addr)
        
    def idc_add_segm_ex(self, start, end, base, use32, name, sclass, *args):
        if not all(isinstance(i, int) for i in [start, end, base, use32]): return
        new_seg = Segment(
            name, start, end, base, 
            str(sclass) if sclass else "CODE", 
            bool(use32)
        )
        if not self.db.get_segment_by_selector(base): 
            self.db.segments.append(new_seg)

    def parse_argument(self, arg_str):
        """Parse argument string into Python primitive"""
        arg_str = arg_str.strip()
        if not arg_str:
            return None
            
        # Handle hex numbers (0x prefix)
        if arg_str.startswith('0x'):
            try:
                return int(arg_str, 16)
            except ValueError:
                pass
                
        # Handle decimal numbers
        if arg_str.isdigit():
            return int(arg_str)
            
        # Handle strings
        if arg_str.startswith('"') and arg_str.endswith('"'):
            return arg_str[1:-1].encode('latin-1').decode('unicode_escape')
            
        # Handle simple expressions (e.g., 0x1000 + 4)
        try:
            return eval(arg_str, {"__builtins__": None}, {})
        except:
            logger.warning(f"Could not parse argument: {arg_str}")
            return None

    def execute_script(self, filepath: str):
        logger.info(f"Executing IDC script: {filepath}")
        try:
            with open(filepath, 'r', encoding='latin-1') as f:
                script_content = f.read()
            return self.execute_script_from_content(script_content)
        except Exception as e:
            logger.error(f"Error processing IDC script '{filepath}': {e}", exc_info=True)
            raise
            
    def execute_script_from_content(self, script_content: str):
        """Execute IDC script content directly"""
        logger.info("Executing IDC script from content")
        try:
            # Find all function calls in the script
            for match in self.func_regex.finditer(script_content):
                func_name = match.group(1)
                args_str = match.group(2).strip()
                start_pos = match.start()
                
                # Calculate line number
                line_num = script_content.count('\n', 0, start_pos) + 1
                
                # Skip empty calls
                if not args_str:
                    args = []
                else:
                    # Split arguments while handling quoted strings
                    arg_strs = self.arg_split_regex.split(args_str)
                    args = []
                    for a in arg_strs:
                        parsed = self.parse_argument(a)
                        if parsed is None:
                            logger.warning(
                                f"Line {line_num}: Could not parse argument: {a}"
                            )
                        args.append(parsed)
                
                # Execute the function if it's in our map
                if func_name in self.function_map:
                    try:
                        self.function_map[func_name](*args)
                    except Exception as e:
                        logger.warning(
                            f"Line {line_num}: Error executing '{func_name}({', '.join(map(str, args))})': {e}"
                        )
        except Exception as e:
            logger.error(f"Fatal error processing IDC script: {e}", exc_info=True)
            raise