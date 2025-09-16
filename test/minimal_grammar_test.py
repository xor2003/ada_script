import unittest
import sys
sys.path.append('/home/xor/ada_script')
from idc_engine_fixed import IDCParser

class TestMinimalGrammar(unittest.TestCase):
    def setUp(self):
        self.parser = IDCParser()

    def test_bitwise_operator(self):
        script = "x = y & z;"
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)

    def test_shift_operator(self):
        script = "x = y << 2;"
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)

    def test_for_loop(self):
        script = "for (i=0; i<10; i=i+1) {}"
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)

    def test_preprocessor(self):
        script = "#include <idc.idc>\nx = 1;"
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)

    def test_type_declaration(self):
        script = "auto i, j, k;"
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)

if __name__ == '__main__':
    unittest.main()