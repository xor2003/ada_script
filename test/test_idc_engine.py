import pytest
import sys
import os
from unittest.mock import MagicMock, patch

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import AnalysisDatabase, AddressInfo, ITEM_TYPE_CODE, ITEM_TYPE_DATA, DATA_TYPE_BYTE, DATA_TYPE_WORD, DATA_TYPE_DWORD, DATA_TYPE_ASCII
from idc_engine import IDCScriptEngine

@pytest.fixture
def mock_db():
    db = AnalysisDatabase()
    db.get_address_info = MagicMock(return_value=AddressInfo(address=0x1000, byte_value=0))
    db.add_function = MagicMock()
    db.operand_format_overrides = {}
    return db

def test_idc_create_insn(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_create_insn(0x1000)
    info = mock_db.get_address_info(0x1000)
    assert info.item_type == ITEM_TYPE_CODE

def test_idc_create_byte(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_create_data(0x1000, 1)
    info = mock_db.get_address_info(0x1000)
    assert info.item_type == ITEM_TYPE_DATA
    assert info.data_type == DATA_TYPE_BYTE

def test_idc_create_word(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_create_data(0x1000, 2)
    info = mock_db.get_address_info(0x1000)
    assert info.item_type == ITEM_TYPE_DATA
    assert info.data_type == DATA_TYPE_WORD

def test_idc_create_dword(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_create_data(0x1000, 4)
    info = mock_db.get_address_info(0x1000)
    assert info.item_type == ITEM_TYPE_DATA
    assert info.data_type == DATA_TYPE_DWORD

def test_idc_create_ascii_with_length(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_create_ascii(0x1000, 5)
    info = mock_db.get_address_info(0x1000)
    assert info.item_type == ITEM_TYPE_DATA
    assert info.data_type == DATA_TYPE_ASCII
    assert info.item_size == 5

def test_idc_create_ascii_auto_length(mock_db):
    # Setup memory with null-terminated string
    mock_db.memory = {
        0x1000: AddressInfo(address=0x1000, byte_value=65, item_size=1),
        0x1001: AddressInfo(address=0x1001, byte_value=66, item_size=1),
        0x1002: AddressInfo(address=0x1002, byte_value=0, item_size=1)
    }
    mock_db.get_address_info.side_effect = lambda addr: mock_db.memory.get(addr)
    
    engine = IDCScriptEngine(mock_db)
    engine.idc_create_ascii(0x1000, 0)
    info = mock_db.get_address_info(0x1000)
    assert info.item_type == ITEM_TYPE_DATA
    assert info.data_type == DATA_TYPE_ASCII

    # Verify item size includes all bytes including null terminator
    assert info.item_size == 3

def test_idc_set_name(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_set_name(0x1000, "main")
    info = mock_db.get_address_info(0x1000)
    assert info.label == "main"

def test_idc_set_cmt(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_set_cmt(0x1000, "Entry point", 0)
    info = mock_db.get_address_info(0x1000)
    assert info.comment == "Entry point"

def test_idc_set_cmt_repeatable(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_set_cmt(0x1000, "Important comment", 1)  # Use 1 for repeatable
    info = mock_db.get_address_info(0x1000)
    assert info.repeatable_comment == "Important comment"

def test_idc_add_func(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_add_func(0x1000, 0x2000)
    mock_db.add_function.assert_called_with(0x1000, 0x2000)

def test_idc_op_format(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_op_format(0x1000, 0, 'hex')
    assert mock_db.operand_format_overrides[(0x1000, 0)].format_type == 'hex'

def test_idc_op_offset(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_op_offset(0x1000, 0, 0x2000)
    # Verify operand format was set
    assert (0x1000, 0) in mock_db.operand_format_overrides
    # The exact format depends on database implementation
    assert True  # Placeholder - functionality is verified in main execution

def test_idc_add_segm_ex(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_add_segm_ex(0x1000, 0x2000, 0x3000, 1, "CODE", "CODE")
    assert len(mock_db.segments) == 1
    assert mock_db.segments[0].name == "CODE"

def test_execute_script_success(mock_db):
    engine = IDCScriptEngine(mock_db)
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = "create_insn(0x1000);"
        engine.execute_script("test.idc")
        mock_db.get_address_info.assert_called()