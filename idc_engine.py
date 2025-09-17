
import logging
import os
import re
import traceback
from lark import Lark, Transformer, v_args, Token, Tree
from database import (
    AnalysisDatabase, ITEM_TYPE_CODE, ITEM_TYPE_DATA, DATA_TYPE_ASCII,
    DATA_TYPE_BYTE, DATA_TYPE_WORD, DATA_TYPE_DWORD,
    Segment, Function, OperandFormat
)

logger = logging.getLogger(__name__)

idc_grammar = r"""
    ?start: item*

    ?item: statement
         | function_definition
         | preprocessor
         | declaration

    preprocessor: /#.*/
    declaration: ("auto" | "extern") CNAME ("," CNAME)* ("=" expr)? ";" -> ignore

    function_definition: "static" CNAME "(" [parameters] ")" block
    parameters: (parameter ("," parameter)*)?
    parameter: CNAME

    block: "{" item* "}"

    ?statement: if_statement
              | for_statement
              | while_statement
              | do_while_statement
              | return_statement
              | break_statement
              | continue_statement
              | try_statement
              | throw_statement
              | empty_statement
              | expr_statement
              | block

    expr_statement: expr ";"
    if_statement: "if" "(" expr ")" block ("else" block)?
    for_statement: "for" "(" [expr] ";" [expr] ";" [expr] ")" block
    while_statement: "while" "(" expr ")" block
    do_while_statement: "do" statement "while" "(" expr ")" ";" -> ignore
    return_statement: "return" [expr] ";"
    break_statement: "break" ";"
    continue_statement: "continue" ";"
    try_statement: "try" statement "catch" "(" CNAME ")" statement
    throw_statement: "throw" expr ";"
    empty_statement: ";"

    ?expr: assignment | ternary_expr
    assignment: CNAME "=" expr

    ?ternary_expr: logical_or_expr ("?" expr ":" ternary_expr)*
    ?logical_or_expr: logical_and_expr ("||" logical_and_expr)*
    ?logical_and_expr: bitwise_or_expr ("&&" bitwise_or_expr)*
    ?bitwise_or_expr: bitwise_xor_expr ("|" bitwise_xor_expr)*
    ?bitwise_xor_expr: bitwise_and_expr ("^" bitwise_and_expr)*
    ?bitwise_and_expr: equality_expr ("&" equality_expr)*
    ?equality_expr: relational_expr (("==" | "!=") relational_expr)*
    ?relational_expr: shift_expr (("<" | ">" | "<=" | ">=") shift_expr)*
    ?shift_expr: additive_expr (("<<" | ">>") additive_expr)*
    ?additive_expr: multiplicative_expr (("+" | "-") multiplicative_expr)*
    ?multiplicative_expr: unary_expr (("*" | "/" | "%") unary_expr)*
    ?unary_expr: (unary_op)* atom
    unary_op: "!" | "~" | "&" | "-" | "++" | "--"

    ?atom: literal
         | CNAME -> identifier
         | "(" expr ")"
         | call_expr

    call_expr: CNAME "(" [arguments] ")"
    arguments: (expr ("," expr)*)?

    ?literal: HEX_NUMBER -> number
            | SIGNED_INT -> number
            | ESCAPED_STRING -> string

    HEX_NUMBER.2: /0[xX][0-9a-fA-F]+/

    %import common.CNAME
    %import common.SIGNED_INT
    %import common.ESCAPED_STRING
    %import common.WS

    %ignore WS
    %ignore /\/\/[^\n]*/
    %ignore /\/\*(\*(?!\/)|[^*])*\*\//
"""

class IDCParser:
    def __init__(self, start='start'):
        self.parser = Lark(
            idc_grammar,
            start=start,
            parser='lalr',
            transformer=IDCTransformer()
        )
    
    def parse(self, text):
        return self.parser.parse(text)

class IDCTransformer(Transformer):
    def __init__(self):
        super().__init__()
        self.variables = {}
        # No need for self.statements or _use_meta

    def safe_extract_value(self, node):
        """Safely extract the value from a Lark node, recursing if it's a Tree."""
        if isinstance(node, Token):
            return node.value
        elif isinstance(node, Tree):
            # Recurse to the first terminal child (common case)
            for child in node.children:
                if isinstance(child, Token):
                    return child.value
            # If no direct terminal, try the data or str
            return str(node.data) if hasattr(node, 'data') else str(node)
        else:
            # Fallback for unexpected nodes
            raise ValueError(f"Unsupported node type: {type(node)} for value extraction")

    def number(self, n):
        val_str = self.safe_extract_value(n[0])
        return int(val_str, 0)
    
    def string(self, s):
        val_str = self.safe_extract_value(s[0])
        return val_str[1:-1].encode('latin-1').decode('unicode_escape')
    
    def identifier(self, i):
        val_str = self.safe_extract_value(i[0])
        return self.variables.get(val_str, val_str)

    def assignment(self, items):
        # Handle both cases: [var, '=', value] and [var, value] (from ternary)
        if len(items) == 3:
            var_name = self.safe_extract_value(items[0])
            value = items[2]
            self.variables[var_name] = value
            return value
        else:
            # Handle ternary assignment: [value]
            return items[0]

    def _reduce_ops(self, items):
        val = items[0]
        i = 1
        while i < len(items):
            # Break if we don't have operator and operand
            if i+1 >= len(items):
                break
                
            # Handle both Token objects and string operators
            op_node = items[i]
            op_str = op_node.value if hasattr(op_node, 'value') or isinstance(op_node, Token) else str(op_node)
            right = items[i+1]
            i += 2  # Move to next operator
            
            if not isinstance(val, int) or not isinstance(right, int):
                # Skip non-integer operations
                continue
            if op_str == '+': val += right
            elif op_str == '-': val -= right
            elif op_str == '*': val *= right
            elif op_str == '/': val //= right if right != 0 else 0
            elif op_str == '|': val |= right
            elif op_str == '&': val &= right
            elif op_str == '^': val ^= right
            elif op_str == '<<': val <<= right
            elif op_str == '>>': val >>= right
        return val

    additive_expr = multiplicative_expr = bitwise_or_expr = bitwise_xor_expr = bitwise_and_expr = shift_expr = _reduce_ops

    def unary_expr(self, items):
        val = items[-1]
        for op_node in reversed(items[:-1]):
            op_str = self.safe_extract_value(op_node) if hasattr(op_node, 'value') or isinstance(op_node, Token) else str(op_node)
            if op_str == '-' and isinstance(val, int): val = -val
            if op_str == '~' and isinstance(val, int): val = ~val
            if op_str == '++' and isinstance(val, int): val += 1
            if op_str == '--' and isinstance(val, int): val -= 1
        return val

    def arguments(self, args):
        # Return a simple list of arguments
        return args
    
    def call_expr(self, items):
        func_name = self.safe_extract_value(items[0])
        args = items[1] if len(items) > 1 else []
        return ("call", func_name, args)

    def expr_statement(self, items):
        return items[0]

    def if_statement(self, items):
        condition = items[0]
        true_branch = items[1]
        false_branch = items[2] if len(items) > 2 else None
        return ('if', condition, true_branch, false_branch)
    
    def while_statement(self, items):
        return None
    
    def for_statement(self, items):
        return None
    
    def function_definition(self, items):
        return None
    
    def start(self, items):
        # The start rule just collects all the items (statements).
        # Filter out None from statements that don't produce output.
        return [item for item in items if item is not None]

    # Remove redundant statement handlers
    
    
    

class IDCScriptEngine:
    def __init__(self, db: AnalysisDatabase):
        self.db = db
        self.function_map = self._initialize_function_map()

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
            "MakeFunction": self.idc_add_func,
            "MakeName": self.idc_set_name,
            **{k: self.idc_no_op for k in ["update_extra_cmt", "set_frame_size", "define_local_var", "op_enum",
            "op_stroff", "op_stkvar", "op_seg", "SegRename", "SegClass", "SegDefReg", "set_segm_type",
            "split_sreg_range", "delete_all_segments", "add_enum", "add_enum_member", "add_struc", "add_struc_member",
            "get_struc_id", "get_member_id", "SetType", "set_struc_align", "set_processor_type", "set_inf_attr",
            "set_flag", "add_default_til", "begin_type_updating", "end_type_updating", "make_array", "get_inf_attr", "GetEnum"]}
        }

    def idc_no_op(self, *args, **kwargs): return 0
    def idc_create_insn(self, addr):
        if not isinstance(addr, int): return
        if info := self.db.get_address_info(addr):
            info.item_type = ITEM_TYPE_CODE
            info.item_size = 1
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
                info = self.db.get_address_info(curr_addr); length += 1
                if not info or info.byte_value == 0: break
                curr_addr += 1
        if info := self.db.get_address_info(addr):
            info.item_type, info.item_size, info.data_type = ITEM_TYPE_DATA, length, DATA_TYPE_ASCII
        for i in range(1, length):
            if info_rest := self.db.get_address_info(addr + i): info_rest.item_type, info_rest.data_type = ITEM_TYPE_DATA, DATA_TYPE_ASCII
    def idc_set_name(self, addr, name, *args):
        if not isinstance(addr, int): return
        if info := self.db.get_address_info(addr): info.label = name
    def idc_set_cmt(self, addr, comment, repeatable=0, *args):
        if not isinstance(addr, int): return
        is_repeatable = bool(int(repeatable)) if str(repeatable).isdigit() else False
        if info := self.db.get_address_info(addr):
            if is_repeatable: info.repeatable_comment = comment
            else: info.comment = comment
    def idc_op_format(self, addr, op_index, fmt_type):
        if not isinstance(addr, int): return
        self.db.operand_format_overrides[(addr, op_index)] = OperandFormat(fmt_type)
    def idc_add_func(self, start_addr, end_addr):
        if not isinstance(start_addr, int) or not isinstance(end_addr, int): return
        self.db.add_function(start_addr, end_addr)
        
    def idc_add_segm_ex(self, start, end, base, use32, name, sclass, *args):
        if not all(isinstance(i, int) for i in [start, end, base, use32]): return
        new_seg = Segment(name, start, end, base, str(sclass) if sclass else "CODE", bool(use32))
        if not self.db.get_segment_by_selector(base): self.db.segments.append(new_seg)
        
    def idc_op_offset(self, addr, op_index, base):
        if not isinstance(addr, int): return
        self.db.operand_format_overrides[(addr, op_index)] = OperandFormat('offset', base)
        
    def execute_script_from_content(self, script: str):
        """Execute an IDC script from a string content."""
        try:
            parser = IDCParser()
            statements = parser.parse(script)
            if not isinstance(statements, list):
                statements = [statements] if statements is not None else []
            for stmt in statements:
                if isinstance(stmt, tuple) and len(stmt) > 1 and stmt[0] == "call":
                    _, func_name, args = stmt
                    if func_name in self.function_map:
                        try:
                            self.function_map[func_name](*args)
                        except Exception as e:
                            logger.error(f"Error in IDC function {func_name}: {e}")
                    else:
                        logger.warning(f"IDC Warning: Unknown function {func_name}")
        except Exception as e:
            logger.error(f"Error executing IDC script: {e}\n{traceback.format_exc()}")

    def execute_script(self, filepath: str):
        logger.info(f"Executing IDC script: {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                script_content = f.read()
            self.execute_script_from_content(script_content)
        except FileNotFoundError:
            logger.error(f"IDC script file not found: {filepath}")
        except Exception as e:
            logger.error(f"Error reading IDC script file: {e}")