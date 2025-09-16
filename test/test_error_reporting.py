import unittest
import logging
import os
import sys
from unittest.mock import MagicMock, patch

# Add parent directory to path to import idc_engine
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from idc_engine import IDCScriptEngine

class TestIDCErrorReporting(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        # Create a real IDCScriptEngine with mocked database
        self.db_mock = MagicMock()
        self.engine = IDCScriptEngine(self.db_mock)
        
    def test_unparseable_argument(self):
        """Test that unparseable arguments log warnings with line numbers"""
        with patch('idc_engine.logger.warning') as mock_warning:
            test_script = """
            create_insn(0x1000);
            set_name(0x2000, invalid[argument]);
            """
            
            self.engine.execute_script_from_content(test_script)
                
            # Verify warning was logged for unparseable argument
            self.assertTrue(mock_warning.called)
            warning_message = mock_warning.call_args[0][0]
            self.assertIn("Could not parse argument", warning_message)
            self.assertIn("Line 3", warning_message)  # Line number of the problematic call

    def test_valid_script_no_errors(self):
        """Test that valid scripts don't produce error messages"""
        with patch('idc_engine.logger.error') as mock_error, \
             patch('idc_engine.logger.warning') as mock_warning:
            # Create a valid test script
            test_script = """
            create_insn(0x1000);
            set_name(0x2000, "valid_label");
            """
            
            # Execute the script
            self.engine.execute_script_from_content(test_script)
                
            # Verify no errors or warnings were logged
            self.assertFalse(mock_error.called)
            self.assertFalse(mock_warning.called)

if __name__ == '__main__':
    unittest.main()