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