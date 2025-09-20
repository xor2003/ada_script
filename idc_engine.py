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
empty_stmt: SEMI

?param_list: param ("," param)*
?param: [type] NAME

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
arg_list: [expression ("," expression)*]

path_content: /[^>]+/

NAME: /[a-zA-Z_][a-zA-Z0-9_]*/
STRING: /"[^"]*"/
NUMBER: /0[xX][0-9a-fA-F]+|\d+/

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
            raise SyntaxError(f"Syntax error at line {e.line}, column {e.column}: {e}") from e
        except Exception as e:
            raise e


# Main parsing function
def parse_idc(script_path, mz_data=None, strict=False):
    with open(script_path, 'r') as f:
        content = f.read()

    grammar = IDCGrammar()
    try:
        script = grammar.parse(content)
        if mz_data:
            pass
        return script
    except SyntaxError as e:
        if strict:
            raise
        logging.warning(f"IDC parse warning: {e}")
        return None


if __name__ == "__main__":
    # Example usage
    grammar = IDCGrammar()
    result = grammar.parse("""
    #include <some_header.idc>
    #define UNLOADED_FILE 1
    static byte my_var;
    auto base = 0x10000;
    static main() {
        set_name("example", "Test");
    }
    """)
    print(result)