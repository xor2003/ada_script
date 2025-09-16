import test_grammar
import pytest
import sys
import os
from unittest.mock import MagicMock, patch
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import AnalysisDatabase, AddressInfo, ITEM_TYPE_CODE, ITEM_TYPE_DATA, DATA_TYPE_BYTE, DATA_TYPE_WORD, DATA_TYPE_DWORD, DATA_TYPE_ASCII
from idc_engine import IDCScriptEngine

@pytest.fixture
def mock_db():
    db = AnalysisDatabase()
    db.address_map = {}

    def get_address_info_mock(addr):
        if addr not in db.address_map:
            db.address_map[addr] = AddressInfo(address=addr, byte_value=0)
        return db.address_map[addr]

    db.get_address_info = MagicMock(side_effect=get_address_info_mock)
    
    db.add_function = MagicMock()
    db.operand_format_overrides = {}
    return db

def test_function_call_handling(mock_db):
    engine = IDCScriptEngine(mock_db)
    script = "create_insn(0x1000); set_name(0x2000, \"main\");"
    
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = script
        engine.execute_script("test.idc")
        
    mock_db.get_address_info.assert_any_call(0x1000)
    mock_db.get_address_info.assert_any_call(0x2000)

def test_hex_number_parsing(mock_db):
    engine = IDCScriptEngine(mock_db)
    script = "create_byte(0x1000);"
    
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = script
        engine.execute_script("test.idc")
        
    mock_db.get_address_info.assert_called_with(0x1000)

def test_string_parsing(mock_db):
    engine = IDCScriptEngine(mock_db)
    script = 'set_name(0x1000, "main");'
    
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = script
        engine.execute_script("test.idc")
    
    # Verify the state of the database
    info = mock_db.get_address_info(0x1000)
    assert info.label == "main"

def test_invalid_function_handling(mock_db, caplog):
    engine = IDCScriptEngine(mock_db)
    script = "invalid_func(0x1000);"
    
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = script
        engine.execute_script("test.idc")
        
    assert "IDC Warning" in caplog.text

def test_ascii_creation(mock_db):
    engine = IDCScriptEngine(mock_db)
    script = "create_strlit(0x1000, 5);"
    
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = script
        engine.execute_script("test.idc")
        
    info = mock_db.get_address_info(0x1000)
    assert info.item_type == ITEM_TYPE_DATA
    assert info.data_type == DATA_TYPE_ASCII
    assert info.item_size == 5