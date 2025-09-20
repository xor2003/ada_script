from lark import Lark, Transformer, v_args, Tree, Token
from lark.exceptions import UnexpectedToken, UnexpectedCharacters

# This grammar resolves the final set of ambiguities and parsing errors.
# - The 'declaration' rule is broken into specific sub-rules to eliminate ambiguity.
# - A specific rule for 'set_name_stmt' is added to satisfy test requirements.
IDC_GRAMMAR = r"""
start: (statement | NEWLINE)*

statement: statement_content SEMI? NEWLINE?

statement_content: include
                  | define_stmt
                  | declaration
                  | function_def
                  | set_name_stmt
                  | function_call_stmt
                  | assignment_stmt
                  | return_stmt
                  | empty_stmt

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

assignment_stmt: NAME ASSIGN expression
function_def: STATIC NAME LP (VOID | param_list)? RP LBRACE (statement | NEWLINE)* RBRACE
set_name_stmt: "set_name" LP arg_list RP
function_call_stmt: function_call
return_stmt: RETURN [expression]
empty_stmt: SEMI

?param_list: param ("," param)*
?param: [type] NAME

?arg: (NAME ASSIGN)? expression
type: BYTE | WORD | DWORD | QWORD

?expression: bitwise_or
?bitwise_or: bitwise_and ("|" bitwise_and)*
?bitwise_and: term ("&" term)*
?term: factor (("+" | "-") factor)*
?factor: unary (("*" | "/") unary)*
?unary: ("+" | "-" | "~") unary | atom

?atom: NUMBER
     | STRING
     | NAME
     | function_call
     | "(" expression ")"

function_call: NAME LP [arg_list] RP
arg_list: [arg ("," arg)*]

path_content: /[^>]+/

// Keywords must come before NAME to avoid tokenization issues
RETURN: "return"
STATIC: "static"
AUTO: "auto"
HASH: "#"
DEFINE: "define"
LT: "<"
GT: ">"
LP: "("
RP: ")"
LBRACE: "{"
RBRACE: "}"
SEMI: ";"
ASSIGN: "="
COMMA: ","

BYTE: "byte"
WORD: "word"
DWORD: "dword"
QWORD: "qword"

INCLUDE: "include"
VOID: "void"

// Generic NAME last
NAME: /[a-zA-Z_][a-zA-Z0-9_]*/

STRING: /"(?s:(?:[^"\\]|\\.)*)"/
NUMBER: /0[xX][0-9a-fA-F]+|\d+/

%import common.NEWLINE
%import common.WS
%ignore WS
%ignore /\/\/[^\n]*/
"""

class IDCTransformer(Transformer):
    def start(self, children):
        script = IDCScript()
        for child in children:
            if isinstance(child, Tree) and child.data == 'statement':
                if child.children and isinstance(child.children[0], Tree):
                    content = child.children[0]
                    if isinstance(content, Tree):
                        payload = content.children[0]
                        if isinstance(payload, str):
                            # include returns str
                            script.includes.append(payload)
                        elif isinstance(payload, dict):
                            if 'value' in payload and 'name' in payload:
                                # define
                                script.defines.append(payload)
                            elif 'statements' in payload:
                                # function_def
                                script.functions.append(payload)
                            else:
                                # declaration dict
                                script.variables.append(payload)
                        elif isinstance(payload, Tree):
                            if payload.data == 'declaration':
                                # declaration tree with sub-decl dict
                                script.variables.append(payload.children[0])
        return script

    def include(self, children):
        return children[3].children[0].value

    def define_stmt(self, children):
        name = children[2].value
        value = children[3] if len(children) > 3 else None
        return {'name': name, 'value': value}

    def _create_decl(self, modifier, dtype, name, init_expr):
        return {'modifier': modifier, 'type': dtype, 'name': name, 'init': init_expr}

    def decl_with_type_and_init(self, children):
        return self._create_decl(children[0].value, children[1].children[0].value, children[2].value, children[4])

    def decl_with_type_no_init(self, children):
        return self._create_decl(children[0].value, children[1].children[0].value, children[2].value, None)

    def decl_no_type_with_init(self, children):
        return self._create_decl(children[0].value, None, children[1].value, children[3])

    def decl_no_type_no_init(self, children):
        return self._create_decl(children[0].value, None, children[1].value, None)

    def function_def(self, children):
        name = children[1].value
        statements = []
        brace_start = -1
        for idx, child in enumerate(children):
            if isinstance(child, Token) and child.type == 'LBRACE':
                brace_start = idx + 1
                break
        if brace_start == -1:
            return {'name': name, 'modifier': 'static', 'statements': []}
        i = brace_start
        while i < len(children):
            child = children[i]
            if isinstance(child, Token) and child.type == 'RBRACE':
                break
            if isinstance(child, Tree) and child.data == 'statement':
                stmt_content = child.children[0]
                if isinstance(stmt_content, Tree) and stmt_content.data == 'statement_content' and len(stmt_content.children) > 0:
                    inner = stmt_content.children[0]
                    statements.append(inner)
            i += 1
        return {'name': name, 'modifier': 'static', 'statements': statements}

    def return_stmt(self, children):
        if len(children) > 1:
            return {'type': 'return', 'value': children[1]}
        else:
            return {'type': 'return', 'value': None}

    def set_name_stmt(self, children):
        args = children[1] if len(children) > 1 else []
        return Tree('set_name_stmt', [{'args': args}])

    def function_call_stmt(self, children):
        return children[0]

    # Expression and atom transformers to pass values up
    def expression(self, children): return children[0]
    def bitwise_or(self, children): return children[0]
    def bitwise_and(self, children): return children[0]
    def term(self, children): return children[0]
    def factor(self, children): return children[0]
    def unary(self, children): return children[0]
    def atom(self, children): return children[0]
    def arg_list(self, children):
        return [c for c in children if not isinstance(c, Token) or c.type != 'COMMA']

    def arg(self, children):
        if len(children) == 1:
            return children[0]  # positional expression
        elif len(children) == 3:
            name = children[0].value
            expr = children[2]
            return {'name': name, 'expr': expr}
        else:
            raise ValueError(f"Invalid arg structure: {children}")

    @v_args(inline=True)
    def STRING(self, s):
        return s[1:-1]

    @v_args(inline=True)
    def NUMBER(self, n):
        return n.value

    def __default__(self, data, children, meta):
        return Tree(data, children, meta)


class IDCScript:
    def __init__(self, includes=None, defines=None, variables=None, functions=None):
        self.includes = includes or []
        self.defines = defines or []
        self.variables = variables or []
        self.functions = functions or []

    def __repr__(self):
        return f"IDCScript(includes={len(self.includes)}, defines={len(self.defines)}, variables={len(self.variables)}, functions={len(self.functions)})"


class IDCGrammar:
    def __init__(self):
        self.parser = Lark(IDC_GRAMMAR, start='start', parser='lalr', transformer=IDCTransformer())

    def parse(self, text):
        try:
            return self.parser.parse(text)
        except (UnexpectedToken, UnexpectedCharacters) as e:
            error_msg = f"Syntax error at line {e.line}, column {e.column}: {e}\n"
            error_msg += f"Unexpected token: {e.token}\n"
            error_msg += f"Expected one of: {', '.join(e.expected)}\n"
            if hasattr(e, 'context') and e.context:
                error_msg += f"Previous tokens: {[str(t) for t in e.context]}\n"
            elif hasattr(e, 'token_history') and e.token_history:
                error_msg += f"Previous tokens: {[str(t) for t in e.token_history]}\n"
            else:
                error_msg += "Previous tokens: []\n"
            error_msg += f"Line content: {text.splitlines()[e.line-1] if e.line <= len(text.splitlines()) else 'EOF'}\n"
            raise SyntaxError(error_msg) from e
        except Exception as e:
            error_msg = f"Parser error: {e}\n"
            if hasattr(e, 'line') and hasattr(e, 'column'):
                error_msg += f"Location: line {e.line}, column {e.column}\n"
            raise SyntaxError(error_msg) from e


# Main parsing function
def parse_idc(script_path, mz_data=None, strict=False):
    import logging
    try:
        with open(script_path, 'r') as f:
            content = f.read()
        print(f"[DEBUG] Parsing IDC file: {script_path}")
        print(f"[DEBUG] File content length: {len(content)} characters")
    except FileNotFoundError:
        raise FileNotFoundError(f"IDC script not found: {script_path}")

    grammar = IDCGrammar()
    try:
        script = grammar.parse(content)
        print(f"[DEBUG] IDC parsed successfully: {len(script.includes)} includes, {len(script.defines)} defines, {len(script.variables)} variables, {len(script.functions)} functions")
        if mz_data:
            print(f"[DEBUG] MZ data provided: {len(mz_data)} sections")
            # Apply IDC to MZ (stub)
            print("[DEBUG] Applying IDC to MZ data...")
        return script
    except SyntaxError as e:
        error_msg = f"[ERROR] IDC parsing failed at {script_path}: {e}\n"
        error_msg += f"[DEBUG] Error type: {type(e).__name__}\n"
        if hasattr(e, 'line') and hasattr(e, 'column'):
            error_msg += f"[DEBUG] Error location: line {e.line}, column {e.column}\n"
            lines = content.splitlines()
            if e.line <= len(lines):
                error_msg += f"[DEBUG] Line {e.line}: {lines[e.line-1]}\n"
                # Highlight position
                if hasattr(e, 'column'):
                    line_content = lines[e.line-1]
                    error_msg += f"[DEBUG] Pointer: {line_content[:e.column-1]}{'^' * (len(str(e.token)) if hasattr(e, 'token') else 1)}\n"
        print(error_msg)
        if strict:
            raise
        print("[DEBUG] Continuing with partial parse or None")
        return None
    except Exception as e:
        error_msg = f"[ERROR] Unexpected error parsing IDC: {e}\n"
        error_msg += f"[DEBUG] Error type: {type(e).__name__}\n"
        import traceback
        error_msg += f"[DEBUG] Traceback: {traceback.format_exc()}\n"
        print(error_msg)
        raise


if __name__ == "__main__":
    # Example usage
    import sys
    if len(sys.argv) > 1:
        result = parse_idc(sys.argv[1])
        print(result)
    else:
        grammar = IDCGrammar()
        result = grammar.parse("""
        #include <some_header.idc>
        #define UNLOADED_FILE 1
        static byte my_var;
        auto base = 0x10000;
        static main() {
            set_name("example", "Test");
            return 0;
        }
        """)
        print(result)