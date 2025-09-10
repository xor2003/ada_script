"""
idc_engine.py: Parses and executes IDA-compatible IDC scripts to override auto-analysis.
"""

import sys
from lark import Lark, Transformer, v_args
from database import (
    AnalysisDatabase, ITEM_TYPE_CODE, ITEM_TYPE_DATA, DATA_TYPE_ASCII,
    Segment, Function, OperandFormat
)

idc_grammar = r"""
    ?start: statement*
    statement: CNAME "(" [arguments] ")" ";"
    arguments: argument ("," argument)*
    ?argument: literal
    ?literal: SIGNED_INT -> number
            | ESCAPED_STRING -> string
            | CNAME -> identifier
    %import common.CNAME
    %import common.SIGNED_INT
    %import common.ESCAPED_STRING
    %import common.WS
    %ignore WS
    %ignore /\/\/.*/
"""

@v_args(inline=True)
class IDCTransformer(Transformer):
    def number(self, n):
        return int(n, 0) # Handles hex, dec, oct
    def string(self, s):
        return s[1:-1].encode('latin-1').decode('unicode_escape')
    def identifier(self, i):
        return str(i)
    def arguments(self, *args):
        return list(args)
    def statement(self, func_name, args=None):
        return str(func_name), args or []

class IDCScriptEngine:
    def __init__(self, db: AnalysisDatabase):
        self.db = db
        self.parser = Lark(idc_grammar, start='start')
        self.transformer = IDCTransformer()
        self.function_map = self._initialize_function_map()

    def _initialize_function_map(self):
        return {
            "create_insn": self.idc_create_insn,
            "create_byte": lambda addr: self.idc_create_data(addr, 1),
            "create_word": lambda addr: self.idc_create_data(addr, 2),
            "create_dword": lambda addr: self.idc_create_data(addr, 4),
            "create_ascii": self.idc_create_ascii,
            "set_name": self.idc_set_name,
            "set_cmt": self.idc_set_cmt,
            "op_hex": lambda addr, n: self.idc_op_format(addr, n, 'hex'),
            "op_dec": lambda addr, n: self.idc_op_format(addr, n, 'dec'),
            "op_offset": self.idc_op_offset,
            "add_func": self.idc_add_func,
        }

    def execute_script(self, filepath: str):
        print(f"[*] Executing IDC script: {filepath}")
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            tree = self.parser.parse(content)
            statements = self.transformer.transform(tree).children
            for i, (func_name, args) in enumerate(statements):
                self._execute_statement(func_name, args, i + 1)
        except Exception as e:
            print(f"[!] Error in IDC script: {e}", file=sys.stderr)

    def _execute_statement(self, func_name: str, args: list, line_num: int):
        if func_name in self.function_map:
            try:
                self.function_map[func_name](*args)
            except TypeError as e:
                print(f"[!] IDC Error (line {line_num}): Incorrect arguments for '{func_name}'. {e}", file=sys.stderr)
        else:
            print(f"[!] IDC Warning (line {line_num}): Unsupported function '{func_name}'.", file=sys.stderr)

    def idc_create_insn(self, addr):
        info = self.db.get_address_info(addr)
        if info: info.item_type = ITEM_TYPE_CODE

    def idc_create_data(self, addr, size):
        for i in range(size):
            info = self.db.get_address_info(addr + i)
            if info:
                info.item_type = ITEM_TYPE_DATA
                info.item_size = size if i == 0 else 1
                if size == 4: info.data_type = 4
                elif size == 2: info.data_type = 2
                else: info.data_type = 1

    def idc_create_ascii(self, addr, length):
        if length == 0:
            curr_addr, length = addr, 0
            while True:
                info = self.db.get_address_info(curr_addr)
                length += 1
                if not info or info.byte_value == 0: break
                curr_addr += 1
        for i in range(length):
            info = self.db.get_address_info(addr + i)
            if info:
                info.item_type = ITEM_TYPE_DATA
                info.item_size = length if i == 0 else 1
                info.data_type = DATA_TYPE_ASCII

    def idc_set_name(self, addr, name):
        info = self.db.get_address_info(addr)
        if info: info.label = name

    def idc_set_cmt(self, addr, comment, repeatable):
        info = self.db.get_address_info(addr)
        if info:
            if repeatable: info.repeatable_comment = comment
            else: info.comment = comment

    def idc_op_format(self, addr, op_index, fmt_type):
        self.db.operand_format_overrides[(addr, op_index)] = OperandFormat(format_type=fmt_type)

    def idc_op_offset(self, addr, op_index, base):
        self.db.operand_format_overrides[(addr, op_index)] = OperandFormat(format_type='offset', value=base)

    def idc_add_func(self, start_addr, end_addr):
        self.db.add_function(start_addr, end_addr)
