import pytest
from unittest.mock import MagicMock, patch
from database import AnalysisDatabase, AddressInfo, OperandFormat, ITEM_TYPE_CODE, ITEM_TYPE_DATA, DATA_TYPE_BYTE, DATA_TYPE_WORD, DATA_TYPE_DWORD, DATA_TYPE_ASCII
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
    mock_db.memory = {
        0x1000: AddressInfo(address=0x1000, byte_value=65),
        0x1001: AddressInfo(address=0x1001, byte_value=66),
        0x1002: AddressInfo(address=0x1002, byte_value=0)
    }
    mock_db.get_address_info.side_effect = lambda addr: mock_db.memory.get(addr)
    
    engine = IDCScriptEngine(mock_db)
    engine.idc_create_ascii(0x1000, 0)
    info = mock_db.get_address_info(0x1000)
    assert info.item_type == ITEM_TYPE_DATA
    assert info.data_type == DATA_TYPE_ASCII
    assert info.item_size == 3

def test_idc_set_name(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_set_name(0x1000, "my_label")
    info = mock_db.get_address_info(0x1000)
    assert info.label == "my_label"

def test_idc_set_cmt_repeatable(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_set_cmt(0x1000, "Important comment", True)
    info = mock_db.get_address_info(0x1000)
    assert info.repeatable_comment == "Important comment"

def test_idc_set_cmt_regular(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_set_cmt(0x1000, "Regular comment", False)
    info = mock_db.get_address_info(0x1000)
    assert info.comment == "Regular comment"

def test_idc_op_format_hex(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_op_format(0x1000, 0, "hex")
    assert mock_db.operand_format_overrides[(0x1000, 0)] == OperandFormat(format_type="hex")

def test_idc_op_format_dec(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_op_format(0x1000, 1, "dec")
    assert mock_db.operand_format_overrides[(0x1000, 1)] == OperandFormat(format_type="dec")

def test_idc_op_offset(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_op_offset(0x1000, 0, 0x2000)
    assert mock_db.operand_format_overrides[(0x1000, 0)] == OperandFormat(format_type="offset", value=0x2000)

def test_idc_add_func(mock_db):
    engine = IDCScriptEngine(mock_db)
    engine.idc_add_func(0x1000, 0x2000)
    mock_db.add_function.assert_called_with(0x1000, 0x2000)

def test_execute_script():
    # Create a real database instance
    db = AnalysisDatabase()

    # Add address info to the database
    addr_info = AddressInfo(address=4096, byte_value=0)
    db.memory[4096] = addr_info

    engine = IDCScriptEngine(db)
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.return_value.__enter__.return_value.readlines.return_value = [
            "create_insn(4096);\n",
            "set_name(4096, \"main\");\n",
            "set_cmt(4096, \"Entry point\", 0);\n",
            "GenInfo();\n",
            "Segments();\n",
            "Enums();\n",
            "Structures();\n",
            "ApplyStrucTInfos();\n",
            "Patches();\n",
            "SegRegs();\n",
            "Bytes();\n",
            "Functions();\n",
            "add_default_til();\n",
            "begin_type_updating();\n",
            "end_type_updating();\n",
            "op_seg(4096, 0);\n",
            "op_stkvar(4096, 0);\n",
            "set_flag(4096, 0);\n",
            "set_inf_attr(4096, 0);\n",
            "set_processor_type(0);\n",
            "set_struc_align(0);\n",
            "delete_all_segments();\n"
        ]
        engine.execute_script("test.idc")

    # Verify the address info was modified
    assert db.memory[4096].item_type == ITEM_TYPE_CODE
    assert db.memory[4096].label == "main"
    assert db.memory[4096].comment == "Entry point"