import unittest
import logging
from unittest.mock import patch, MagicMock
from mz_parser import load_mz_exe
from database import AnalysisDatabase

class TestMZParser(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        self.db = AnalysisDatabase()

    def test_invalid_mz_header(self):
        """Test that invalid MZ headers are properly rejected"""
        with patch('builtins.open', create=True) as mock_open:
            # Create a mock file that returns invalid header
            mock_open.return_value.__enter__.return_value.read.return_value = b'XX'
            
            # Try to load the executable
            result = load_mz_exe("invalid.exe", self.db)
            self.assertFalse(result)
            
    def test_valid_mz_header(self):
        """Test that valid MZ headers are accepted"""
        with patch('builtins.open', create=True) as mock_open:
            # Create a mock file with full MZ header
            mock_open.return_value.__enter__.return_value.read.return_value = bytes([
                # MZ header
                0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
                0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ])
            
            # Try to load the executable
            result = load_mz_exe("valid.exe", self.db)
            self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()