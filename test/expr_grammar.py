from lark import Lark, Transformer

expr_grammar = r"""
    ?start: expr

    ?expr: logical_or_expr

    ?logical_or_expr: logical_and_expr ("||" logical_and_expr)*
    ?logical_and_expr: bitwise_or_expr ("&&" bitwise_or_expr)*
    ?bitwise_or_expr: bitwise_xor_expr ("|" bitwise_xor_expr)*
    ?bitwise_xor_expr: bitwise_and_expr ("^" bitwise_and_expr)*
    ?bitwise_and_expr: equality_expr ("&" equality_expr)*
    ?equality_expr: relational_expr (("==" | "!=") relational_expr)*
    ?relational_expr: additive_expr (("<" | ">" | "<=" | ">=") additive_expr)*
    ?additive_expr: multiplicative_expr (("+" | "-") multiplicative_expr)*
    ?multiplicative_expr: unary_expr (("*" | "/" | "%") unary_expr)*
    ?unary_expr: (unary_op)* atom
    unary_op: "!" | "~" | "&" | "-"

    ?atom: literal
         | CNAME
         | "(" expr ")"

    literal: HEX_NUMBER
           | SIGNED_INT

    HEX_NUMBER: /0[xX][0-9a-fA-F]+/
    SIGNED_INT: /-?[0-9]+/

    %import common.CNAME
    %import common.WS
    %ignore WS
"""

class ExprParser:
    def __init__(self):
        self.parser = Lark(
            expr_grammar,
            start='start',
            parser='lalr'
        )
    
    def parse(self, text):
        return self.parser.parse(text)

if __name__ == "__main__":
    parser = ExprParser()
    expr = "val & MASK"
    tree = parser.parse(expr)
    print(tree.pretty())