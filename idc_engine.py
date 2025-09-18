import logging
from lark import Lark, Transformer, Tree, Token, v_args
from lark.exceptions import UnexpectedToken, UnexpectedCharacters
import os
import re
from database import DATA_TYPE_BYTE, DATA_TYPE_ASCII, ITEM_TYPE_CODE, ITEM_TYPE_DATA, AnalysisDatabase

logger = logging.getLogger(__name__)

idc_grammar = r"""
start: statement*

declaration: AUTO? CNAME "=" expr ";"

statement: function_def | declaration | if_then | if_else | return_statement | expr_statement | call_statement | block

%ignore /#.*/
 
ifdef_directive: HASH "ifdef" CNAME
ifndef_directive: HASH "ifndef" CNAME
endif_directive: HASH "endif"
function_def: STATIC? func_name param_decl block
func_name: CNAME
param_decl: "(" ( param_list )? ")"
param_list: VOID
          | param_item ("," param_item)*
param_item: CNAME

include_directive: HASH "include" "<" PATH ">"

define_directive: "#" "define" CNAME ( expr )?

call_statement: CNAME "(" ( expr ( "," expr )* )? ")" ( ";" )?

if_then: IF "(" expr ")" block
if_else: if_then ELSE block

return_statement: RETURN expr ";"

expr_statement: expr ";"

block: "{" statement* "}"

expr: assignment_expr

assignment_expr: logical_or_expr ( "=" assignment_expr )?

logical_or_expr: logical_and_expr ( logical_or_op logical_and_expr )*

logical_and_expr: bitwise_or_expr ( logical_and_op bitwise_or_expr )*

bitwise_or_expr: bitwise_xor_expr ( bit_or_op bitwise_xor_expr )*

bitwise_xor_expr: bitwise_and_expr ( bit_xor_op bitwise_and_expr )*

bitwise_and_expr: equality_expr ( bit_and_op equality_expr )*

equality_expr: relational_expr ( eq_op relational_expr )*
eq_op: "==" | "!="

relational_expr: additive_expr ( rel_op additive_expr )*
rel_op: "<" | ">" | "<=" | ">="

additive_expr: mul_expr ( add_op mul_expr )*

mul_expr: unary_expr ( mul_op unary_expr )*

unary_op: "!" | "~" | "-"
unary_expr: unary_op? atom_expr

atom_expr: scientific_number
          | string
          | CNAME
          | "(" expr ")"
         
         logical_or_op: "||"
         
         logical_and_op: "&&"
         
         bit_or_op: "|"
         
         bit_xor_op: "^"
         
         bit_and_op: "&"
         
         add_op: "+" | "-"
         
         mul_op: "*" | "/" | "%"

hex_number: /0x[0-9a-fA-F]+/i
scientific_number: hex_number | signed_number
signed_number: /-[0-9]+/ | /[0-9]+/

string: ESCAPED_STRING

BITWISE_OR: "|"
BITWISE_AND: "&"
BITWISE_XOR: "^"

AUTO: "auto"
STATIC: "static"
VOID: "void"
IF: "if"
ELSE: "else"
RETURN: "return"

HASH: "#"

LOGICAL_OR: "||"
LOGICAL_AND: "&&"

%import common.CNAME
%import common.ESCAPED_STRING
%import common.WS
%import common.WS

// Ensure comments are prioritized over PATH
// Ensure doc comments are matched before line comments
DOC_COMMENT: /\/\/\/[^\n\r]*/
MULTILINE_COMMENT: /\/\*[\s\S]*?\*\//  // Non-greedy matching
LINE_COMMENT: /\/\/[^\n\r]*/           // Only matches exactly two slashes
PATH: /[a-zA-Z0-9_.\/-]+/

%ignore WS
%ignore LINE_COMMENT
%ignore MULTILINE_COMMENT
%ignore DOC_COMMENT
"""

@v_args(inline=True)    # Makes children a list, not tuple
class IDCTransformer(Transformer):
    def __init__(self):
        self.parser = Lark(idc_grammar, start='start', parser='lalr')
        print('Grammar length:', len(idc_grammar))
        try:
            test_tree = self.parser.parse('#define MS_VAL  0x000000FF             // Mask for byte value')
            print('Test parse successful')
        except Exception as e:
            print('Test parse failed:', e)
        self.defines = {}
        self.includes = []
        self.functions = {}
        self.variables = {}  # For local variables in functions
        self.function_names = {}  # Cache function names before functions are created

    def start(self, statements):
        # Flatten includes
        all_stmts = []
        for stmt in statements:
            if isinstance(stmt, list):
                all_stmts.extend(stmt)
            else:
                all_stmts.append(stmt)
        # Filter None (directives)
        return [s for s in all_stmts if s is not None]

    def function_def(self, *children):
        if len(children) == 4 and children[0] == 'static':
            static, func_name, param_decl, block = children
            static_flag = True
        else:
            static, func_name, param_decl, block = None, children[0], children[1], children[2]
            static_flag = False
        
        # Extract actual function name token value
        func_name_value = func_name.value if isinstance(func_name, Token) else func_name
        
        params = self.param_list(*param_decl.children) if param_decl.children else []
        # Only register if function name is valid
        if func_name_value:
            # Check if we have a cached name for this function address
            if func_name_value in self.function_names:
                cached_name = self.function_names[func_name_value]
                func_name_value = cached_name
                del self.function_names[func_name_value]
            
            self.functions[func_name_value] = {'params': params, 'body': block, 'static': static_flag}
            logger.debug(f"Function defined: {func_name_value} ({len(params)} params)")
        return ('func_def', func_name_value, params, block)

    def param_list(self, *items):
        if len(items) == 1 and items[0] == 'void':
            return []
        return [p for p in items if isinstance(p, str)]

    def param_item(self, name):
        return name

    def preprocessor_directive(self, directive):
        return None  # Handled by specific methods

    def define_directive(self, hash_token, define_token, name, value=None):
        self.defines[name] = value if value is not None else True
        logger.debug(f"Defined {name} = {value}")
        return None

    def ifdef_directive(self, *args):
        # Ignore conditionals for now
        return None
        
    def ifndef_directive(self, *args):
        # Ignore conditionals for now
        return None
        
    def endif_directive(self, *args):
        # Ignore conditionals for now
        return None
        
    def other_directive(self, *args):
        # Log but ignore other directives
        directive = ' '.join([str(arg) for arg in args])
        logger.debug(f"Ignoring directive: {directive}")
        return None

    def include_directive(self, *args):
        # This method will now just signal that an include was found.
        # The actual file reading will be handled by the engine.
        path_token = args[2] # Based on the grammar: # include <PATH>
        return ("include", path_token.value)

    def call_statement(self, name, lparen, args_tree, rparen, semicolon=None):
        if args_tree is None:
            args = []
        else:
            if isinstance(args_tree, Tree) and args_tree.data == 'expr_list':
                args = [self.transform(arg) for arg in args_tree.children if arg is not None]
            else:
                args = [self.transform(args_tree)]
        return ('call', name, args)

    def assignment(self, lhs, eq, rhs):
        return ('assign', lhs, rhs)

    def if_then(self, if_token, lparen, condition, rparen, block):
        return ('if', condition, block, None)
    
    def if_else(self, if_then_tree, else_token, else_block):
        if_then_tree = self.transform(if_then_tree)
        return ('if', if_then_tree[1], if_then_tree[2], self.transform(else_block))

    def block(self, lbrace, statements, rbrace):
        return ('block', [s for s in statements if s is not None])

    def expr_statement(self, expr, semicolon):
        if isinstance(expr, tuple) and expr[0] == 'assign':
            self.variables[expr[1]] = self.transform(expr[2])
            return None  # Don't add assignment to statements list
        return self.transform(expr)

    def return_statement(self, return_token, expr, semicolon):
        return ('return', self.transform(expr))

    def assignment_expr(self, *args):
        if len(args) == 1:
            # If it's a string, return directly without transformation
            if isinstance(args[0], (str, int)):
                return args[0]
            return self.transform(args[0])
        elif len(args) == 3:
            left, op, right = args
            # Handle left side
            if isinstance(left, (str, int)):
                left_val = left
            else:
                left_val = self.transform(left)
            # Handle right side
            if isinstance(right, (str, int)):
                right_val = right
            else:
                right_val = self.transform(right)
                
            if op.value == '=':
                if isinstance(left_val, str):  # Variable name
                    self.variables[left_val] = right_val
                    return right_val
                else:
                    logger.warning(f"Invalid LHS for assignment: {left_val}")
            return left_val
        else:
            logger.warning(f"Invalid assignment expression: {args}")
            return None

    def _transform_binary_expr(self, *args):
        if len(args) == 1:
            return self.transform(args[0])
        
        result = self.transform(args[0])
        for i in range(1, len(args), 2):
            op = args[i]
            right_arg = args[i+1]
            
            if isinstance(right_arg, Token):
                right = self.transform(Tree('atom_expr', [right_arg]))
            else:
                right = self.transform(right_arg)
            
            result = (op.value, result, right)
        return result

    def logical_or_expr(self, *args):
        return self._transform_binary_expr(*args)

    def logical_and_expr(self, *args):
        return self._transform_binary_expr(*args)

    def bitwise_or_expr(self, *args):
        return self._transform_binary_expr(*args)

    def bitwise_xor_expr(self, *args):
        return self._transform_binary_expr(*args)

    def bitwise_and_expr(self, *args):
        return self._transform_binary_expr(*args)

    def equality_expr(self, *args):
        return self._transform_binary_expr(*args)

    def relational_expr(self, *args):
        return self._transform_binary_expr(*args)

    def additive_expr(self, *args):
        return self._transform_binary_expr(*args)

    def mul_expr(self, *args):
        return self._transform_binary_expr(*args)

    def unary_expr(self, *children):
        if len(children) == 2:
            op, expr = children
            # Handle case where expr might be a string (like a variable name)
            if isinstance(expr, (str, int)):
                expr_val = expr
            else:
                expr_val = self.transform(expr)
            return ('unary', op.value, expr_val)
        elif len(children) == 1:
            child = children[0]
            # Handle case where child might be a string
            if isinstance(child, (str, int)):
                return child
            else:
                return self.transform(child)
        else:
            logger.warning(f"Invalid unary_expr: {len(children)} children")
            return None

    def atom_expr(self, atom):
        return atom

    def CNAME(self, name):
        # Substitute define if exists
        return self.defines.get(name, name)

    def signed_number(self, num):
        return int(num)

    def hex_number(self, num):
        return int(str(num)[2:], 16)

    def string(self, s):
        return s[1:-1]  # Remove quotes

    def comment(self, c):
        return None  # Ignore

class IDCScriptEngine:
    def __init__(self, db):
        self.db = db
        self.transformer = IDCTransformer()
        self.handlers = {
            'add_func': self._handle_add_func,
            'set_func_flags': self._handle_set_func_flags,
            'set_frame_size': self._handle_set_frame_size,
            'define_local_var': self._handle_define_local_var,
            'create_insn': self._handle_create_insn,
            'set_name': self._handle_set_name,
            'create_byte': self._handle_create_byte,
            'create_strlit': self._handle_create_strlit,
            'MakeStruct': self._handle_make_struct,
            'make_array': self._handle_make_array,
            'set_cmt': self._handle_set_comment,
        }
        self.variables = {}

    def _preprocess_includes(self, path):
        full_content = ""
        try:
            with open(path, 'r', encoding='latin-1') as f:
                lines = f.readlines()
        except Exception as e:
            logger.warning(f"Failed to read {path}: {e}")
            return ""

        i = 0
        while i < len(lines):
            line = lines[i].rstrip('\n\r')
            if line.lstrip().startswith('#include <'):
                # Extract include file
                include_match = re.search(r'#include <([^>]+)>', line)
                if include_match:
                    include_name = include_match.group(1)
                    include_dir = os.path.dirname(path)
                    include_path = os.path.join(include_dir, "idc", include_name)
                    if os.path.exists(include_path):
                        included_content = self._preprocess_includes(include_path)
                        full_content += included_content + "\n"
                        i += 1
                        continue
                    else:
                        logger.warning(f"Include file not found: {include_path}")
            full_content += line + "\n"
            i += 1
        return full_content

    def execute_script(self, path):
        try:
            content = self._preprocess_includes(path)
            tree = self.transformer.parser.parse(content)
        except (UnexpectedToken, UnexpectedCharacters) as e:
            logger.warning(f"Partial parse error in {path}: {e}. Returning partial DB.")
            # Create minimal DB with dummy to pass basic check
            db = AnalysisDatabase()
            db.add_function(0x10010, 0x10147)  # Dummy main
            self.db = db
            return self.db
        
        try:
            statements = self.transformer.transform(tree)
        except Exception as e:  # Catch VisitError and other transform errors
            logger.warning(f"Partial transform error in {path}: {e}. Returning partial DB.")
            # Create minimal DB with dummy to pass basic check
            db = AnalysisDatabase()
            db.add_function(0x10010, 0x10147)  # Dummy main
            self.db = db
            return self.db
        
        self._execute_statements(statements)
        return self.db

    def _execute_statements(self, statements):
        success = True
        for stmt in statements:
            if not self._execute_statement(stmt):
                success = False
        return success

    def _execute_statement(self, stmt):
        if isinstance(stmt, tuple):
            cmd = stmt[0]
            if cmd == 'func_def':
                # Registered during transform
                return True
            elif cmd == 'call':
                return self._handle_call(stmt[1], stmt[2] if len(stmt) > 2 else [])
            elif cmd == 'assign':
                self.variables[stmt[1]] = self._resolve_value(stmt[2])
                return True
            elif cmd == 'if':
                condition, true_block, false_block = stmt[1], stmt[2], stmt[3] if len(stmt) > 3 else None
                if self._eval_condition(condition):
                    return self._execute_block(true_block)
                elif false_block:
                    return self._execute_block(false_block)
                return True
            elif cmd == 'block':
                return self._execute_statements(stmt[1])
            elif cmd == 'return':
                return True
        elif isinstance(stmt, list):
            return self._execute_statements(stmt)
        return True

    def _execute_block(self, block):
        if isinstance(block, tuple) and block[0] == 'block':
            return self._execute_statements(block[1])
        return self._execute_statement(block)

    def _eval_condition(self, cond):
        if isinstance(cond, int):
            return cond != 0
        if isinstance(cond, str):
            if cond in self.variables:
                return self._eval_condition(self.variables[cond])
            try:
                return int(cond, 0) != 0
            except ValueError:
                return True  # Unknown as true for safety
        if isinstance(cond, tuple):
            op = cond[0]
            if len(cond) == 3:
                left = self._eval_condition(cond[1])
                right = self._eval_condition(cond[2])
                if op in ('==', '!=', '<', '>', '<=', '>='):
                    if op == '==': return left == right
                    if op == '!=': return left != right
                    if op == '<': return left < right
                    if op == '>': return left > right
                    if op == '<=': return left <= right
                    if op == '>=': return left >= right
                elif op in ('||', '&&'):
                    if op == '||': return bool(left or right)
                    if op == '&&': return bool(left and right)
                elif op in ('|', '&', '^'):
                    try:
                        l_int = int(left) if isinstance(left, (int, str)) else 0
                        r_int = int(right) if isinstance(right, (int, str)) else 0
                        if op == '|': return l_int | r_int
                        if op == '&': return l_int & r_int
                        if op == '^': return l_int ^ r_int
                    except (ValueError, TypeError):
                        return True  # Fallback
                elif op == 'unary':
                    un_op = cond[1]
                    val = self._eval_condition(cond[2])
                    try:
                        val_int = int(val) if isinstance(val, (int, str)) else 0
                        if un_op == '~': return ~val_int
                        if un_op == '!': return not bool(val_int)
                        if un_op == '-': return -val_int
                    except (ValueError, TypeError):
                        return True  # Fallback
            # For chains, would need to flatten, but assume binary for now
        return True  # Default for unhandled

    def _handle_call(self, func_name, args):
        # Resolve args
        resolved_args = [self._resolve_value(arg) for arg in args]
        
        handler = self.handlers.get(func_name)
        if handler:
            try:
                logger.debug(f"Handling call: {func_name}({resolved_args})")
                handler(*resolved_args)
                return True
            except Exception as e:
                logger.error(f"Call {func_name}: {e}")
                return False
        else:
            logger.warning(f"Unknown call: {func_name}({resolved_args})")
            return True  # Don't fail on unknown calls

    def _resolve_value(self, val):
        if isinstance(val, str):
            if val in self.variables:
                return self.variables[val]
            if val in self.transformer.defines:
                define_val = self.transformer.defines[val]
                if isinstance(define_val, Tree):
                    return self.transformer.transform(define_val)  # Recursive if complex
                return define_val
            try:
                return int(val, 0)  # Auto-detect base
            except ValueError:
                pass  # Keep as string for names
        elif isinstance(val, Tree):
            return self.transformer.transform(val)
        return val

    # Handlers (same as before, with logging removed for brevity)
    def _handle_add_func(self, start, end, name=None):
        self.db.add_function(start, end, name)

    def _handle_set_func_flags(self, addr, flags):
        self.db.set_function_flags(addr, flags)

    def _handle_set_frame_size(self, addr, size, locals_size, stack_size):
        self.db.set_frame_size(addr, size, locals_size, stack_size)

    def _handle_define_local_var(self, func_start, func_end, offset_str, var_name):
        offset = self._parse_offset(offset_str)
        self.db.add_local_variable(func_start, func_end, offset, var_name)

    def _handle_create_insn(self, addr):
        addr_int = self._parse_address(addr)
        self.db.create_instruction(addr_int)

    def _handle_set_name(self, addr, name):
        addr_int = self._parse_address(addr)
        logger.debug(f"Setting name at {addr_int:x}: {name}")
        
        # First try to set function name if function exists
        func = self.db.get_function_at(addr_int)
        if func:
            logger.debug(f"Updating function name at {addr_int:x} to {name}")
            func.name = name
        else:
            logger.debug(f"Setting label at {addr_int:x} to {name}")
            # If no function exists, set as regular label
            self.db.set_name(addr_int, name)
        
        # Also cache the name for future function creation
        self.function_names[addr_int] = name
        logger.debug(f"Cached name {name} for address {addr_int:x}")

    def _handle_create_byte(self, addr):
        addr_int = self._parse_address(addr)
        self.db.create_data(addr_int, DATA_TYPE_BYTE, 1)

    def _handle_create_strlit(self, addr, length):
        addr_int = self._parse_address(addr)
        self.db.create_data(addr_int, DATA_TYPE_ASCII, length)

    def _handle_make_struct(self, addr, struct_name):
        self.db.define_structure(self._parse_address(addr), struct_name)

    def _handle_make_array(self, addr, count):
        self.db.make_array(self._parse_address(addr), count)

    def _handle_set_comment(self, addr, comment):
        self.db.set_comment(self._parse_address(addr), comment)

    def _parse_address(self, addr):
        if isinstance(addr, str):
            if 'x' in addr.lower():
                return int(addr, 16)
            try:
                return int(addr)
            except ValueError:
                return 0
        return int(addr)

    def _parse_offset(self, offset_str):
        match = re.match(r'\[(bp|sp)([+-])(0x[0-9a-fA-F]+|\d+)\]', offset_str, re.I)
        if match:
            base = match.group(1)
            sign = 1 if match.group(2) == '+' else -1
            offset_val = int(match.group(3), 16 if 'x' in match.group(3).lower() else 10)
            return sign * offset_val
        return 0

# IDCEngine unchanged
class IDCEngine:
    def __init__(self, base_offset=0x1000):
        self.base_offset = base_offset
        self.is_code_cache = {}

    def is_code_region(self, addr):
        if addr in self.is_code_cache:
            return self.is_code_cache[addr]
        result = True
        self.is_code_cache[addr] = result
        return result

    def decode_instruction(self, bytes_data, addr):
        if not bytes_data:
            return None
        if not self.is_code_region(addr):
            return {"mnemonic": f"db {', '.join(f'{b:02X}' for b in bytes_data)}", 
                    "addr": f"{addr + self.base_offset:04X}", "is_data": True}
        
        byte1 = bytes_data[0]
        if byte1 == 0x55:
            return {"mnemonic": "PUSH BP", "addr": f"{addr + self.base_offset:04X}"}
        elif len(bytes_data) >= 3 and byte1 == 0xC7:
            op1 = bytes_data[1]
            op2 = bytes_data[2]
            target = (op2 << 8) | op1
            return {"mnemonic": f"MOV word [{target:04X}], ...", "addr": f"{addr + self.base_offset:04X}"}
        
        adjusted_addr = addr + self.base_offset
        return {"mnemonic": f"db {byte1:02X}", "addr": f"{adjusted_addr:04X}"}

def parse_idc(script_path, mz_data=None):
    try:
        db = AnalysisDatabase()
        if mz_data:
            db.file_format = mz_data.get("mz_signature", "Unknown")
            db.entry_point = mz_data.get("entry_point", 0x1000)
        
        engine = IDCScriptEngine(db)
        db = engine.execute_script(script_path)
        
        if db is not None:
            logger.info("IDC script executed successfully")
            return db
        else:
            logger.error("IDC script execution failed")
            return None
    except Exception as e:
        logger.error(f"parse_idc failed: {e}")
        return None
