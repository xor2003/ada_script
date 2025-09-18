# test/test_idc_engine.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idc_engine import parse_idc

def test_parse_f15dgtl():
    result = parse_idc('f15dgtl.idc', {})
    assert result is not None
    assert len(result.functions) > 0
    # Check that the main function exists by its address
    assert any(func.start_addr == 0x10010 for func in result.functions.values())

def test_parse_egame():
    result = parse_idc('egame.idc', {})
    assert result is not None
