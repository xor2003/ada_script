import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from idc_engine import IDCParser

class MinimalTest(unittest.TestCase):
    def test_if_statement_block(self):
        parser = IDCParser(start='start')
        script = "if (1) { return 1; }"
        tree = parser.parse(script)
        self.assertIsNotNone(tree, "Parser returned None for if statement with block")
        
        # Test if-else with blocks
        script3 = "if (1) { return 1; } else { return 0; }"
        tree3 = parser.parse(script3)
        self.assertIsNotNone(tree3, "Parser returned None for if-else statement")

if __name__ == '__main__':
    unittest.main()