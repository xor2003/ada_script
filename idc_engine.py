from lark import Lark, Transformer, v_args, Tree, Token
from lark.exceptions import UnexpectedToken, UnexpectedCharacters
import logging, sys

# Comprehensive IDC grammar: Covers commands from tests/egame.idc, full expressions in args, recursive statements.
IDC_GRAMMAR = r"""
// Terminals first
NUMBER: /\d+/

ADD_FUNC: "add_func"
MAKE_STRUCT: "MakeStruct"
CREATE_INSN: "create_insn"
OP_HEX: "op_hex"
OP_STKVAR: "op_stkvar"
OP_ENUM: "op_enum"
OP_PLAIN_OFFSET: "op_plain_offset"
SET_CMT: "set_cmt"
SET_NAME: "set_name"
SET_INF_ATTR: "set_inf_attr"
ADD_SEGM_EX: "add_segm_ex"
SEG_RENAME: "SegRename"
SEG_CLASS: "SegClass"
DELETE_ALL_SEGMENTS: "delete_all_segments"
SET_PROCESSOR_TYPE: "set_processor_type"
GET_INF_ATTR: "get_inf_attr"

NAME: /[a-zA-Z_][a-zA-Z0-9_]*/
STRING: ESCAPED_STRING

// Operators
BITWISE_OR: "|"
BITWISE_AND: "&"
EQ: "=="
NEQ: "!="
LE: "<="
GE: ">="
LSHIFT: "<<"
RSHIFT: ">>"
PLUS: "+"
MINUS: "-"
MUL: "*"
DIV: "/"
MOD: "%"
BITWISE_NOT: "~"
NOT: "!"
DOT: "."
LSBRACKET: "["
RSBRACKET: "]"
LBRACE: "{"
RBRACE: "}"
COMMA: ","
SEMI: ";"
ASSIGN: "="
HASH: "#"
DEFINE: "define"
INCLUDE: "include"
RETURN: "return"
STATIC: "static"
AUTO: "auto"
VOID: "void"
BYTE: "byte"
WORD: "word"
DWORD: "dword"
QWORD: "qword"
LP: "("
RP: ")"
LT: "<"
GT: ">"

// Hex with case-insensitive x/X
hex_addr: /0[xX][0-9A-Fa-f]+/
hex_value: /0[xX][0-9A-Fa-f]+/

path: NAME (DOT NAME)*
path_content: /[^<>\s]+/  // Avoid < > in path

%import common.ESCAPED_STRING
%import common.NEWLINE
%import common.WS
%ignore WS
%ignore /\/\/[^\n]*/
%ignore /\/\*[\s\S]*?\*\//

// Rules
start: (statement | NEWLINE)*

statement: statement_content SEMI? NEWLINE?

statement_content: include
                 | define_stmt
                 | declaration
                 | function_def
                 | command_stmt
                 | function_call_stmt
                 | assignment_stmt
                 | return_stmt
                 | empty_stmt

// Expanded: All known IDC cmds from tests (set_inf_attr, add_segm_ex, SegRename, SegClass, delete_all_segments, set_processor_type, etc.)
command_stmt: command_name LP arg_list RP

command_name: ADD_FUNC | MAKE_STRUCT | CREATE_INSN | OP_HEX | OP_STKVAR | OP_ENUM | OP_PLAIN_OFFSET
            | SET_CMT | SET_NAME | SET_INF_ATTR | ADD_SEGM_EX | SEG_RENAME | SEG_CLASS
            | DELETE_ALL_SEGMENTS | SET_PROCESSOR_TYPE | GET_INF_ATTR

arg: expression | NAME ASSIGN expression

arg_list: arg? (COMMA arg)*

include: HASH INCLUDE LT path_content GT

define_stmt: HASH DEFINE NAME [expression]

declaration: decl_with_type_and_init
            | decl_with_type_no_init
            | decl_no_type_with_init
            | decl_no_type_no_init

decl_with_type_and_init: (STATIC | AUTO) type NAME ASSIGN expression
decl_with_type_no_init: (STATIC | AUTO) type NAME
decl_no_type_with_init: (STATIC | AUTO) NAME ASSIGN expression
decl_no_type_no_init: (STATIC | AUTO) NAME

return_stmt: RETURN [expression]

assignment_stmt: NAME ASSIGN expression

function_def: STATIC NAME LP (VOID | param_list)? RP LBRACE statements RBRACE

function_call_stmt: function_call

empty_stmt: SEMI

?statements: (statement | NEWLINE)*  // Recursive for body

?param_list: param (COMMA param)*
?param: [type] NAME

type: BYTE | WORD | DWORD | QWORD | "void"

?expression: bitwise_or
?bitwise_or: bitwise_and (BITWISE_OR bitwise_and)*
?bitwise_and: equality (BITWISE_AND equality)*
?equality: relational (EQ | NEQ relational)*
?relational: shift ("<" | ">" | LE | GE shift)*
?shift: additive (LSHIFT | RSHIFT additive)*
?additive: multiplicative ((PLUS | MINUS) multiplicative)*
?multiplicative: unary (MUL | DIV | MOD unary)*
?unary: (PLUS | MINUS | BITWISE_NOT | NOT) unary | postfix
?postfix: primary (LSBRACKET expression RSBRACKET | DOT NAME | function_call)*
?primary: NUMBER
         | hex_value
         | STRING
         | NAME
         | LP expression RP
         | function_call

function_call: NAME LP arg_list RP
"""

class IDCTransformer(Transformer):
    def __init__(self):
        super().__init__(visit_tokens=True)

    def start(self, children):
        import logging
        logging.debug(f"Transformer start: {len(children)} children, types={[type(c).__name__ for c in children[:5]]}")
        script = IDCScript()
        processed = 0
        for child in children:
            if isinstance(child, Tree):
                logging.debug(f"Processing Tree: data={child.data}, children_len={len(child.children)}")
                payload = self.transform(child)
                logging.debug(f"Tree {child.data} transformed: {type(payload).__name__ if payload else 'None'}{' (payload: ' + str(payload) + ')' if isinstance(payload, str) else ''}")
                if isinstance(payload, str):
                    if payload.strip():
                        script.includes.append(payload.strip())
                        processed += 1
                elif isinstance(payload, Token):
                    if payload.value.strip():
                        script.includes.append(payload.value.strip())
                        processed += 1
                elif isinstance(payload, dict):
                    self._add_item_to_script(script, payload)
                    processed += 1
                elif isinstance(payload, list):
                    for p in payload:
                        if isinstance(p, dict):
                            self._add_item_to_script(script, p)
                            processed += 1
            elif isinstance(child, str) and child.strip():
                script.includes.append(child.strip())
                processed += 1
            elif isinstance(child, Token) and child.value.strip():
                script.includes.append(child.value.strip())
                processed += 1
            elif isinstance(child, dict):
                self._add_item_to_script(script, child)
                processed += 1
            elif isinstance(child, list):
                for p in child:
                    if isinstance(p, dict):
                        self._add_item_to_script(script, p)
                        processed += 1
        logging.debug(f"Processed {processed} items; script summary: includes={len(script.includes)}, defines={len(script.defines)}, vars={len(script.variables)}, funcs={len(script.functions)}")
        return script

    def _add_item_to_script(self, script, item):
        import logging
        item_type = item.get('type')
        logging.debug(f"Adding to script: type={item_type}, item={item}")
        if item_type == 'define':
            script.defines.append(item)
        elif item_type == 'function':
            script.functions.append(item)
            # Recurse into statements to extract inner calls to top-level lists
            for stmt in item.get('statements', []):
                if isinstance(stmt, dict):
                    self._add_item_to_script(script, stmt)
        elif 'modifier' in item:
            script.variables.append(item)
        elif item_type == 'call':
            name = item.get('name', '')
            if name == 'add_func':
                script.functions.append(item)
            elif name == 'MakeStruct':
                script.variables.append(item)
            elif name == 'create_insn':
                if not hasattr(script, 'instructions'):
                    script.instructions = []
                script.instructions.append(item)
            elif name == 'set_cmt':
                if not hasattr(script, 'comments'):
                    script.comments = []
                script.comments.append(item)
            elif name == 'set_name':
                if not hasattr(script, 'names'):
                    script.names = {}
                args = item.get('args', [])
                if len(args) >= 2:
                    addr = args[0] if isinstance(args[0], (int, str)) else 0
                    name_val = args[1] if isinstance(args[1], str) else ''
                    script.names[addr] = name_val
            else:
                if not hasattr(script, 'operands'):
                    script.operands = []
                script.operands.append(item)
        # Removed unused: set_cmt/set_name handled in 'call' block now
        elif item_type in ['return', 'assign']:
            pass  # Ignore top-level in functions

    def statement(self, children):
        import logging
        logging.debug(f"Statement children: {len(children)}, filtered={[type(c).__name__ for c in children]}")
        content = [c for c in children if c not in [';', '\n']]
        if content:
            return content[0]
        return None

    def statement_content(self, children):
        import logging
        logging.debug(f"Statement_content: {len(children)} children, first={children[0] if children else 'None'}")
        return children[0] if children else None

    def include(self, children):
        import logging
        path_idx = 3 if len(children) == 5 else 2 if len(children) == 3 else None
        path = children[path_idx] if path_idx is not None else ''
        if isinstance(path, Token):
            path = path.value
        logging.debug(f"Include parsed: children={children}, path={path}")
        return path

    def path(self, children):
        names = [c for c in children if c != '.']
        return '.'.join(names)

    def define_stmt(self, children):
        import logging
        name = children[2] if len(children) >= 3 else ''
        value = children[3] if len(children) > 3 else None
        result = {'type': 'define', 'name': name, 'value': str(value) if value is not None else None}
        logging.debug(f"Define parsed: {result}")
        return result

    def _create_decl(self, modifier, dtype, name, init_expr):
        return {'modifier': modifier, 'type': dtype, 'name': name, 'init': init_expr}

    def decl_with_type_and_init(self, children):
        if len(children) == 5:
            return self._create_decl(children[0], children[1], children[2], children[4])
        return {}

    def decl_with_type_no_init(self, children):
        if len(children) == 3:
            return self._create_decl(children[0], children[1], children[2], None)
        return {}

    def decl_no_type_with_init(self, children):
        if len(children) == 4:
            return self._create_decl(children[0], None, children[1], children[3])
        return {}

    def decl_no_type_no_init(self, children):
        if len(children) == 2:
            return self._create_decl(children[0], None, children[1], None)
        return {}

    def declaration(self, children):
        import logging
        logging.debug(f"Declaration children: {[type(c).__name__ for c in children]}")
        for child in children:
            if child:
                logging.debug(f"Declaration returning: {child}")
                return child
        return {}

    def function_def(self, children):
        import logging
        name = children[1]
        # Handle params
        params = []
        if len(children) > 3:
            params_tree = children[3]
            if isinstance(params_tree, Token):
                if params_tree.value in ['void', ')']:
                    params = []
                else:
                    params = [params_tree]
            elif isinstance(params_tree, Tree):
                params = [c for c in params_tree.children if c is not None]
            else:
                params = params_tree or []
        # Handle statements
        statements = []
        if len(children) > 5:
            if len(children) == 7:  # no params
                statements_tree = children[5]
            else:  # with params or VOID
                statements_tree = children[6]
            if isinstance(statements_tree, Tree):
                statements = [c for c in statements_tree.children if c and not (isinstance(c, Token) and c.type == 'NEWLINE')]
            else:
                statements = statements_tree or []
        if not isinstance(statements, list):
            statements = [statements]
        result = {'type': 'function', 'name': name, 'params': params, 'modifier': 'static', 'statements': statements}
        logging.debug(f"Function_def parsed: {result['name']}, params_len={len(params)}")
        return result

    def statements(self, children):
        return [c for c in children if c and not (isinstance(c, Token) and c.type == 'NEWLINE')]

    def _flatten_statements(self, tree):
        if isinstance(tree, Tree) and tree.data == 'statements':
            return [self.transform(c) for c in tree.children if c and not (isinstance(c, Token) and c.type == 'NEWLINE')]
        elif isinstance(tree, list):
            return tree
        else:
            return []

    @v_args(inline=True)
    def command_stmt(self, name, lp, args, rp):
        import logging
        logging.info(f"command_stmt name: {name}, args: {args}")
        result = {'type': 'call', 'name': name, 'args': args or []}
        logging.debug(f"Command parsed: {name}, args_len={len(result['args'])}")
        return result

    @v_args(inline=True)
    def arg_list(self, *args):
        return [a for a in args if a is not None]

    @v_args(inline=True)
    def arg(self, *children):
        if len(children) == 3 and children[1] == '=':
            return {'type': 'assign', 'left': children[0], 'op': '=', 'right': children[2]}
        elif len(children) == 1:
            return children[0]
        else:
            raise ValueError(f"Unexpected arg children: {children}")

    @v_args(inline=True)
    def return_stmt(self, kw, expr=None):
        return {'type': 'return', 'expr': expr}

    @v_args(inline=True)
    def assignment_stmt(self, name, op, expr):
        return {'type': 'assign', 'name': name, 'op': op, 'expr': expr}

    @v_args(inline=True)
    def function_call(self, name, lp, args, rp):
        import logging
        logging.info(f"function_call name: {name}, args: {args}")
        return {'type': 'call', 'name': name, 'args': args or []}

    def function_call_stmt(self, children):
        return children[0] if children else {'type': 'call', 'name': '', 'args': []}

    def assignment(self, children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'assign', 'left': left, 'op': op, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def arg(self, *children):
        if len(children) == 3 and children[1] == '=':
            return {'type': 'assign', 'left': children[0], 'op': '=', 'right': children[2]}
        elif len(children) == 1:
            return children[0]
        else:
            raise ValueError(f"Unexpected arg children: {children}")

    @v_args(inline=True)
    def bitwise_or(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def bitwise_and(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def equality(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def relational(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def shift(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def additive(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left

    @v_args(inline=True)
    def multiplicative(self, *children):
        if len(children) == 1:
            return children[0]
        left = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            right = children[i + 1]
            left = {'type': 'binary', 'op': op, 'left': left, 'right': right}
            i += 2
        return left


    @v_args(inline=True)
    def unary(self, op, operand):
        return {'type': 'unary', 'op': op, 'operand': operand}

    def conditional_expr(self, children):
        return self.bitwise_or(children)

    def postfix(self, children):
        base = children[0]
        i = 1
        while i < len(children):
            op = children[i]
            if op == '[':
                index = children[i + 1]
                base = {'type': 'index', 'base': base, 'index': index}
                i += 3
            elif op == '.':
                member = children[i + 1]
                base = {'type': 'dot', 'base': base, 'member': member}
                i += 2
            elif op == '(':
                args = children[i + 1] if isinstance(children[i + 1], list) else [children[i + 1]]
                base = {'type': 'call', 'base': base, 'args': args}
                i += 3
            else:
                i += 1
        return base

    @v_args(inline=True)
    def primary(self, value):
        return value

    def simple_assign(self, children):
        left = children[0]
        op = children[1]
        right = children[2]
        return {'type': 'assign', 'left': left, 'op': op, 'right': right}

    def simple_assignment(self, children):
        left = children[0]
        op = children[1]
        right = children[2]
        return {'type': 'assign', 'left': left, 'op': op, 'right': right}

    @v_args(inline=True)
    def NUMBER(self, n): return int(n)

    @v_args(inline=True)
    def hex_value(self, s): return int(s, 16)

    @v_args(inline=True)
    def hex_addr(self, s): return int(s, 16)

    @v_args(inline=True)
    def STRING(self, s):
        if s.startswith('"') and s.endswith('"'):
            s = s[1:-1]
        s = s.replace('\\\\', '\\').replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t')
        return s

    @v_args(inline=True)
    def NAME(self, n): return n

    @v_args(inline=True)
    def path_content(self, s): return s

    @v_args(inline=True)
    def STATIC(self, s): return s

    @v_args(inline=True)
    def AUTO(self, s): return s

    @v_args(inline=True)
    def BYTE(self, s): return s

    @v_args(inline=True)
    def WORD(self, s): return s

    @v_args(inline=True)
    def DWORD(self, s): return s

    @v_args(inline=True)
    def QWORD(self, s): return s

    @v_args(inline=True)
    def VOID(self, s): return s

    @v_args(inline=True)
    def LT(self, s): return s

    @v_args(inline=True)
    def GT(self, s): return s

    @v_args(inline=True)
    def HASH(self, s): return s

    @v_args(inline=True)
    def INCLUDE(self, s): return s

    @v_args(inline=True)
    def DEFINE(self, s): return s

    @v_args(inline=True)
    def RETURN(self, s): return s

    @v_args(inline=True)
    def lt(self, s): return s

    @v_args(inline=True)
    def gt(self, s): return s

    @v_args(inline=True)
    def ADD_FUNC(self, s): return s
    @v_args(inline=True)
    def MAKE_STRUCT(self, s): return s
    @v_args(inline=True)
    def CREATE_INSN(self, s): return s
    @v_args(inline=True)
    def OP_HEX(self, s): return s
    @v_args(inline=True)
    def OP_STKVAR(self, s): return s
    @v_args(inline=True)
    def OP_ENUM(self, s): return s
    @v_args(inline=True)
    def OP_PLAIN_OFFSET(self, s): return s
    @v_args(inline=True)
    def SET_CMT(self, s): return s
    @v_args(inline=True)
    def SET_NAME(self, s): return s
    @v_args(inline=True)
    def SET_INF_ATTR(self, s): return s
    @v_args(inline=True)
    def ADD_SEGM_EX(self, s): return s
    @v_args(inline=True)
    def SEG_RENAME(self, s): return s
    @v_args(inline=True)
    def SEG_CLASS(self, s): return s
    @v_args(inline=True)
    def DELETE_ALL_SEGMENTS(self, s): return s
    @v_args(inline=True)
    def SET_PROCESSOR_TYPE(self, s): return s
    @v_args(inline=True)
    def GET_INF_ATTR(self, s): return s

    def arg_list(self, children):
        args = [c for c in children if c != ',']
        return args

    def param_list(self, children):
        params = [self.transform(c) for c in children if c != ',']
        return params

    def param(self, children):
        if len(children) == 2:
            return {'type': children[0], 'name': children[1]}
        elif len(children) == 1:
            return {'type': None, 'name': children[0]}
        return {}

    def __default__(self, data, children, meta):
        non_none = [c for c in children if c is not None]
        if not non_none:
            return None
        if len(non_none) == 1:
            return non_none[0]
        return non_none if data in ['statements', 'arg_list', 'param_list'] else Tree(data, non_none)



class IDCScript:
    def __init__(self, includes=None, defines=None, variables=None, functions=None, operands=None, comments=None, names=None, instructions=None, db=None):
        self.includes = includes or []
        self.defines = defines or []
        self.variables = variables or []
        self.functions = functions or []
        self.operands = operands or []
        self.comments = comments or []
        self.names = names or {}
        self.instructions = instructions or []
        self.db = db

    def insert_to_db(self):
        if not self.db:
            return
        # Insert functions (use name if available, else sub_addr)
        for func in self.functions:
            start = func.get('start', 0)
            end = func.get('end', 0)
            name = func.get('name', f"sub_{start:X}")
            self.db.execute("INSERT OR REPLACE INTO functions (start, end, name) VALUES (?, ?, ?)", (start, end, name))
        # Insert symbols/names
        for addr, name in self.names.items():
            self.db.execute("INSERT OR REPLACE INTO symbols (addr, name) VALUES (?, ?)", (addr, name))
            # Update functions if matches start
            self.db.execute("UPDATE functions SET name = ? WHERE start = ?", (name, addr))
        # Insert comments
        for cmt in self.comments:
            addr = cmt.get('addr', 0)
            text = cmt.get('text', '')
            self.db.execute("INSERT OR REPLACE INTO comments (addr, comment) VALUES (?, ?)", (addr, text))
        # Insert instructions from create_insn
        for insn in self.instructions:
            addr = insn.get('addr', 0)
            self.db.execute("INSERT OR IGNORE INTO instructions (addr, size, mnem, op_str, type) VALUES (?, ?, ?, ?, ?)", (addr, 0, '', '', 'code'))  # Stub size/mnem
        # Structs as variables if MakeStruct-like
        for var in self.variables:
            if var.get('type') == 'struct':
                name = var.get('name', '')
                size = var.get('size', 0)
                # Assume custom table or use symbols
                self.db.execute("INSERT OR IGNORE INTO symbols (addr, name) VALUES (?, ?)", (0, f"struct_{name}_{size}"))
        logging.info(f"IDC DB inserts: {len(self.functions)} funcs, {len(self.names)} names, {len(self.comments)} comments")


    def __repr__(self):
        return f"IDCScript(includes={len(self.includes)}, defines={len(self.defines)}, variables={len(self.variables)}, functions={len(self.functions)}, operands={len(self.operands)}, comments={len(self.comments)}, names={len(self.names)})"


class IDCGrammar:
    def __init__(self, strict=True):  # Default to strict for better error handling in tests
        self.strict = strict
        self.parser = Lark(IDC_GRAMMAR, start='start', parser='lalr')
        self.transformer = IDCTransformer()

    def parse(self, text, strict=None):
        import logging
        strict = strict or self.strict
        try:
            tree = self.parser.parse(text)
            logging.debug(f"Parser tree: data={tree.data}, children_len={len(tree.children)}")
            script = self.transformer.transform(tree)
            logging.debug(f"Parse result type: {type(script).__name__}, summary: {script}")
            if strict and (len(script.includes) + len(script.defines) + len(script.variables) + len(script.functions) + len(getattr(script, 'operands', [])) + len(getattr(script, 'comments', [])) + len(script.names) + len(getattr(script, 'instructions', []))) == 0:
                logging.warning("Empty script detected in strict mode")
                raise SyntaxError("Parse resulted in empty script")
            return script
        except (UnexpectedToken, UnexpectedCharacters) as e:
            logging.exception(f"Parse warning")
            if strict:
                raise SyntaxError(str(e)) from e
            return IDCScript()
        except Exception as e:
            logging.exception(f"Parse error")
            if strict:
                raise SyntaxError(str(e)) from e
            return IDCScript()


class IDCEngine:
    def __init__(self, strict=False):
        self.grammar = IDCGrammar(strict=strict)

    def parse(self, content: str, db=None, mz_data=None, strict=False):
        self.grammar.strict = strict
        try:
            script = self.grammar.parse(content, strict=strict)
            if script is None and strict:
                raise SyntaxError("Parse failed completely")
            logging.debug("Lark parse success")
        except (UnexpectedToken, UnexpectedCharacters) as e:
            logging.exception(f"Lark failed: {e}. Falling back to regex if not strict.")
            if strict:
                raise SyntaxError(str(e)) from e
            script = self._regex_fallback(content, db)
        if script is None:
            script = IDCScript()
        script.db = db
        if db:
            script.insert_to_db()
        return script

    def _regex_fallback(self, content, db):
        import re
        script = IDCScript(db=db)
        # Expanded regex for more cmds
        patterns = {
            'add_func': re.compile(r'add_func\s*\(\s*0X([0-9A-Fa-f]+)\s*,\s*0X([0-9A-Fa-f]+)\s*\);?', re.IGNORECASE),
            'MakeStruct': re.compile(r'MakeStruct\s*\(\s*"([^"]+)"\s*,\s*(\d+)\s*\);?', re.IGNORECASE),
            'set_name': re.compile(r'set_name\s*\(0X([0-9A-Fa-f]+),\s*"([^"]*)"\);?', re.IGNORECASE),
            'set_cmt': re.compile(r'set_cmt\s*\(0X([0-9A-Fa-f]+),\s*"([^"]*)",\s*0\);?', re.IGNORECASE),
            'create_insn': re.compile(r'create_insn\s*\(0X([0-9A-Fa-f]+)\);?', re.IGNORECASE),
            'set_inf_attr': re.compile(r'set_inf_attr\s*\(\s*(\w+),\s*(.+?)\s*\);?', re.IGNORECASE),
            'add_segm_ex': re.compile(r'add_segm_ex\s*\(\s*0X([0-9A-Fa-f]+),\s*0X([0-9A-Fa-f]+),\s*0X([0-9A-Fa-f]+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\w+)\s*\);?', re.IGNORECASE),
            'SegRename': re.compile(r'SegRename\s*\(\s*0X([0-9A-Fa-f]+),\s*"([^"]*)"\s*\);?', re.IGNORECASE),
            'SegClass': re.compile(r'SegClass\s*\(\s*0X([0-9A-Fa-f]+),\s*"([^"]*)"\s*\);?', re.IGNORECASE),
        }
        lines = content.splitlines()
        for line in lines:
            line = re.sub(r'\t', ' ', line.strip())
            if not line: continue
            for cmd, pat in patterns.items():
                match = pat.search(line)
                if match:
                    groups = match.groups()
                    if cmd == 'add_func':
                        script.functions.append({'type': cmd, 'start': int(groups[0], 16), 'end': int(groups[1], 16)})
                    elif cmd == 'MakeStruct':
                        script.variables.append({'type': cmd, 'name': groups[0], 'size': int(groups[1])})
                    elif cmd == 'set_name':
                        addr = int(groups[0], 16)
                        script.names[addr] = groups[1]
                    elif cmd == 'set_cmt':
                        addr = int(groups[0], 16)
                        script.comments.append({'type': cmd, 'addr': addr, 'text': groups[1]})
                    elif cmd == 'create_insn':
                        script.instructions.append({'type': cmd, 'addr': int(groups[0], 16)})
                    elif cmd == 'set_inf_attr':
                        attr = groups[0]
                        val = groups[1].strip()
                        script.operands.append({'type': cmd, 'attr': attr, 'value': val})
                    elif cmd == 'add_segm_ex':
                        addrs = [int(g, 16) for g in groups[:3]]
                        nums = [int(g) for g in groups[3:6]]
                        flag = groups[6]
                        script.operands.append({'type': cmd, 'start': addrs[0], 'end': addrs[1], 'align': addrs[2], 'flags': nums, 'sa': flag})
                    elif cmd in ['SegRename', 'SegClass']:
                        addr = int(groups[0], 16)
                        name = groups[1]
                        script.names[addr] = name if cmd == 'SegRename' else f"class_{name}"
                    break
        logging.info(f"Regex fallback: Parsed {len(script.functions)} funcs, {len(script.operands)} ops, etc.")
        return script


# Main parsing function
def parse_idc(content: str, db=None, mz_data=None, strict=False):
    engine = IDCEngine()
    return engine.parse(content, db, mz_data, strict)


if __name__ == "__main__":
    # Example usage
    from database import Database
    db = Database(':memory:')
    result = parse_idc("""
    #include <some_header.idc>
    #define UNLOADED_FILE 1
    static byte my_var;
    __ANON_0 = 0x10013;
    static main() {
        set_name(0x10000, "Test");
        create_insn(x=0x10000);
        op_hex(x, 1);
        set_cmt(0x10000, "Test comment", 0);
    }
    """, db)
    print(result)