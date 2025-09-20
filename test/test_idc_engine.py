import pytest
from idc_engine import IDCGrammar, IDCScript

@pytest.fixture
def grammar():
    """Provides an IDCGrammar instance for tests."""
    return IDCGrammar()

def test_simple_declaration(grammar):
    """Tests parsing of a simple static variable declaration."""
    script = "static byte my_var;"
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)
    assert len(result.variables) == 1
    variable = result.variables[0]
    assert variable['name'] == 'my_var'
    assert variable['modifier'] == 'static'
    assert variable['type'] == 'byte'

def test_failing_function_call_statement(grammar):
    """Tests parsing the complex function call that previously caused a syntax error."""
    script = "set_inf_attr(INF_GENFLAGS, ~INFFL_LOADIDC & get_inf_attr(INF_GENFLAGS));"
    # The main goal is to ensure this does not raise a SyntaxError.
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)

def test_function_definition_parsing(grammar):
    """Tests that a function definition with a body is parsed correctly."""
    script = """
    static GenInfo(void) {
        delete_all_segments();
	    set_processor_type("metapc", SETPROC_USER);
    }
    """
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)
    assert len(result.functions) == 1
    assert result.functions[0]['name'] == 'GenInfo'

def test_include_and_define(grammar):
    """Tests parsing of preprocessor directives."""
    script = """
    #include <idc.idc>
    #define UNLOADED_FILE 1
    """
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)
    assert len(result.includes) == 1
    assert result.includes[0] == 'idc.idc'
    assert len(result.defines) == 1
    assert result.defines[0]['name'] == 'UNLOADED_FILE'
    assert result.defines[0]['value'].strip() == '1'

def test_syntax_error_on_invalid_script(grammar):
    """Tests that malformed IDC code raises a SyntaxError."""
    script = "static my_func(void) {"
    with pytest.raises(SyntaxError):
        grammar.parse(script)

def test_parse_egame_idc_snippet(grammar):
    """Tests a snippet from the problematic egame.idc file."""
    script = """
    static Segments(void) {
        add_segm_ex(0X10000,0X1F882,0X1000,0,1,2,ADDSEG_NOSREG);
        SegRename(0X10000,"seg000");
        SegClass (0X10000,"CODE");
    }
    """
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)
    assert len(result.functions) == 1
    assert result.functions[0]['name'] == 'Segments'
def test_function_def_with_return():
    """Test function_def handles return_stmt dict without .data error."""
    from idc_engine import parse_idc
    idc_content = """
    static test_func() {
        return id;
    }
    """
    # Write temp file for test
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.idc', delete=False) as f:
        f.write(idc_content)
        temp_path = f.name
    try:
        result = parse_idc(temp_path)
        assert result is not None
        assert len(result.functions) == 1
        func = result.functions[0]
        assert 'statements' in func
        assert len(func['statements']) == 1
        stmt = func['statements'][0]
        assert isinstance(stmt, dict)
        assert stmt['type'] == 'return'
    finally:
        import os
        os.unlink(temp_path)
def test_multi_line_string_in_arg():
    """Test parsing multi-line strings with escapes in function args."""
    from idc_engine import parse_idc
    from lark import Tree
    idc_content = '''
    static test_func() {
        set_cmt(0x100, "Multi\\nline\\nwith \\"quote\\"", 0);
    }
    '''
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.idc', delete=False) as f:
        f.write(idc_content)
        temp_path = f.name
    try:
        result = parse_idc(temp_path)
        assert result is not None
        assert len(result.functions) == 1
        func = result.functions[0]
        assert 'statements' in func
        # Find set_cmt call (as function_call)
        has_set_cmt = any(isinstance(s, Tree) and s.data == 'function_call' and s.children[0].value == 'set_cmt' for s in func['statements'])
        assert has_set_cmt
    finally:
        import os
        os.unlink(temp_path)