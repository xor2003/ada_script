from lark import Lark, Transformer, v_args, Tree, Token
from lark.exceptions import UnexpectedToken, UnexpectedCharacters
import logging

# This grammar resolves the final set of ambiguities and parsing errors.
# - Statements no longer require a mandatory newline, fixing $END errors.
# - The NUMBER terminal correctly handles both 0x and 0X prefixes.
IDC_GRAMMAR = r"""
?start: (statement | NEWLINE)*

?statement: statement_content SEMI? NEWLINE?

statement_content: include
                 | define_stmt
                 | declaration
                 | function_def
                 | function_call_stmt
                 | assignment_stmt
                 | empty_stmt

include: HASH INCLUDE LT path_content GT
define_stmt: HASH DEFINE NAME [expression]
declaration: (STATIC | AUTO) [type] NAME (ASSIGN expression)?
assignment_stmt: NAME ASSIGN expression
function_def: STATIC NAME LP (VOID | param_list)? RP "{" (statement | NEWLINE)* "}"
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
SEMI: ";"
ASSIGN: "="

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
        includes = []
        defines = []
        variables = []
        functions = []

        for child in filter(None, children):
            if not isinstance(child, Tree):
                continue

            # Unpack from statement -> statement_content
            if child.data == 'statement':
                if not child.children or not isinstance(child.children[0], Tree):
                    continue
                child = child.children[0]

            if child.data == 'statement_content':
                if not child.children or not isinstance(child.children[0], Tree):
                    continue
                child = child.children[0]

            if child.data == 'include':
                includes.append(child.children[0])
            elif child.data == 'define_stmt':
                defines.append(child.children[0])
            elif child.data == 'declaration':
                variables.append(child.children[0])
            elif child.data == 'function_def':
                functions.append(child.children[0])

        return IDCScript(includes=includes, defines=defines, variables=variables, functions=functions)

    def include(self, children):
        return Tree('include', [children[2].value])

    def define_stmt(self, children):
        name = children[2].value
        value = self.transform(children[3]) if len(children) > 3 else None
        return Tree('define_stmt', [{'name': name, 'value': value}])

    def declaration(self, children):
        modifier = children[0].value
        type_node = children[1] if isinstance(children[1], Tree) and children[1].data == 'type' else None
        name_idx = 2 if type_node else 1
        
        dtype = type_node.children[0].value if type_node else None
        name = children[name_idx].value
        
        init_expr = None
        if len(children) > name_idx + 1 and isinstance(children[name_idx+1], Token) and children[name_idx+1].type == 'ASSIGN':
            init_expr = self.transform(children[name_idx+2])

        return Tree('declaration', [{'modifier': modifier, 'type': dtype, 'name': name, 'init': init_expr}])

    def function_def(self, children):
        name = children[1].value
        # Correctly filter and count statements in the function body
        statements = [c for c in children if isinstance(c, Tree) and c.data == 'statement']
        return Tree('function_def', [{'name': name, 'modifier': 'static', 'statements': statements}])

    def expression(self, children):
        # For now, just return a string representation for defines and inits
        # A full expression tree evaluation is out of scope.
        return " ".join(str(c.value) if isinstance(c, Token) else str(c) for c in children)
    
    @v_args(inline=True)
    def NUMBER(self, n):
        return n.value

    def __default__(self, data, children, meta):
        # Fallback for rules that don't have a specific transformer method
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
    """
    Parse IDC script and apply to MZ data (stub for application).
    
    Args:
        script_path: Path to IDC file
        mz_data: Optional MZ data to apply to
        strict: Raise on errors
    
    Returns:
        IDCScript object or None if failed and not strict
    """
    with open(script_path, 'r') as f:
        content = f.read()
    
    grammar = IDCGrammar()
    try:
        script = grammar.parse(content)
        
        # Stub: Apply to mz_data if provided (future: generate patches)
        if mz_data:
            pass
        
        return script
    except SyntaxError as e:
        if strict:
            raise
        logging.warning(f"IDC parse warning: {e}")
        return None  # Or partial parse

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