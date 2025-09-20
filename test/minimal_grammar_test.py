import pytest
from idc_engine import IDCGrammar, parse_idc
from pathlib import Path

def test_minimal_grammar_parses_simple_rules():
    """Test that the minimal grammar parses simple IDC rules."""
    grammar = IDCGrammar()
    
    # Simple IDC snippet
    simple_idc = """
    static byte my_var;
    """
    
    # Parse the simple IDC snippet
    result = grammar.parse(simple_idc)
    
    # Assert it doesn't raise errors and has expected structure
    assert result is not None
    assert len(result.variables) == 1  # Detects static byte declaration
    assert result.variables[0]['name'] == 'my_var'
    assert result.variables[0]['type'] == 'byte'

def test_unknown_keyword_reports_location():
    """Test that unknown keywords are reported with line and column info."""
    grammar = IDCGrammar()
    
    # IDC with unknown keyword
    invalid_idc = """
    unknown_keyword some_var;
    """
    
    with pytest.raises(SyntaxError) as exc_info:
        grammar.parse(invalid_idc)
    
    exc = exc_info.value
    assert "Unknown keyword 'unknown_keyword'" in str(exc)
    assert "line 2, column" in str(exc)

def test_keyword_handling():
    """Test parsing of known IDC keywords like 'static', 'include', etc."""
    grammar = IDCGrammar()
    keyword_test = """
    #include <header>
    static byte my_var;
    """
    
    result = grammar.parse(keyword_test)
    
    # Assert keywords are handled correctly
    assert result is not None
    assert len(result.includes) == 1  # Detects #include
    assert len(result.variables) == 1  # Detects static byte
    assert result.variables[0]['type'] == 'byte'

def test_parse_idc_function():
    """Test the main parse_idc function."""
    # Create a temporary IDC content
    simple_idc = """
    static main() {
        set_name("example", "Test");
    }
    """
    
    # Write to temp file for parse_idc
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.idc', delete=False) as f:
        f.write(simple_idc)
        temp_path = f.name
    
    try:
        result = parse_idc(temp_path)
        assert result is not None
        assert len(result.functions) == 1
        assert result.functions[0]['name'] == 'main'
        # Check the statement
        assert len(result.functions[0]['statements']) == 1
        stmt = result.functions[0]['statements'][0]
        assert stmt.data == 'set_name_stmt'
        assert stmt.children[0]['args'] == ['example', 'Test']
    finally:
        # Clean up temp file
        Path(temp_path).unlink(missing_ok=True)