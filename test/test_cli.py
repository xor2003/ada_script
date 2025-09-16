import pytest
import os
import sys
import logging
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ada import main

def test_cli_with_valid_file(capsys):
    test_args = ["ada", "egame.exe", "-o", "test_output"]
    with patch('sys.argv', test_args), \
         patch('ada.load_mz_exe') as mock_load, \
         patch('ada.EmulationAnalyzer') as mock_analyzer, \
         patch('ada.IDCScriptEngine') as mock_idc, \
         patch('ada.LSTGenerator') as mock_lst, \
         patch('ada.ASMGenerator') as mock_asm:
        
        mock_load.return_value = True
        main()
        
        captured = capsys.readouterr()
        assert "Disassembly Complete" in captured.err
        mock_analyzer.return_value.analyze.assert_called_once()
        mock_lst.return_value.generate.assert_called_with("test_output.lst")
        mock_asm.return_value.generate.assert_called_with("test_output.asm")

def test_cli_missing_file(capsys):
    test_args = ["ada", "missing.exe"]
    with patch('sys.argv', test_args), \
         patch('sys.exit') as mock_exit:
        
        main()
        captured = capsys.readouterr()
        assert "Executable file not found" in captured.err
        mock_exit.assert_called_with(1)

def test_cli_with_idc_script(capsys):
    test_args = ["ada", "egame.exe", "-s", "analysis.idc"]
    with patch('sys.argv', test_args), \
         patch('ada.load_mz_exe') as mock_load, \
         patch('ada.IDCScriptEngine') as mock_idc, \
         patch('os.path.exists') as mock_exists:
        
        mock_load.return_value = True
        mock_exists.return_value = True
        main()
        
        mock_idc.return_value.execute_script.assert_called_with("analysis.idc")

def test_cli_debug_logging(capsys):
    test_args = ["ada", "egame.exe", "--debug"]
    with patch('sys.argv', test_args), \
         patch('ada.load_mz_exe') as mock_load, \
         patch('logging.getLogger') as mock_get_logger:
        
        # Create a mock logger object
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        mock_load.return_value = True
        main()

        # Verify that getLogger was called and setLevel was called on the returned logger
        mock_get_logger.assert_any_call("ada")
        mock_logger.setLevel.assert_called_with(logging.DEBUG)