import unittest
import sys
import os

# Add parent directory to path to import idc_engine
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from idc_engine_fixed import IDCParser

class TestIDCGrammar(unittest.TestCase):
    def setUp(self):
        self.parser = IDCParser()
    
    def test_function_call(self):
        # Test with hex and string arguments
        script = 'add_segm_ex(0X10000,0X1F882,0X1000,0,1,2,ADDSEG_NOSREG);'
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)
        
        # Test with expression arguments
        script = 'SegRename(0X10000,"seg" + "000");'
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)
    
    def test_variable_assignment(self):
        # Test simple assignment
        script = 'id = add_enum(-1,"enum_1",0x1100000);'
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)
        
        # Test chained assignment
        script = 'a = b = 0x100;'
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)
    
    def test_control_structures(self):
        # Test if statement
        script = 'if (get_inf_attr(INF_GENFLAGS) & INFFL_LOADIDC) { return 1; }'
        try:
            tree = self.parser.parse(script)
            self.assertIsNotNone(tree)
        except Exception as e:
            print(f"Error parsing if statement: {e}")
            raise
            
        # Test for loop
        script = 'for (i = 0; i < 10; i = i + 1) { MakeName(i, "array_" + itoa(i)); }'
        try:
            tree = self.parser.parse(script)
            self.assertIsNotNone(tree)
        except Exception as e:
            print(f"Error parsing for loop: {e}")
            raise
    
    def test_preprocessor(self):
        # Test include
        script = '#include <idc.idc>'
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)
        
        # Test define
        script = '#define MAX_ADDR 0xFFFF'
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)
    
    def test_comments(self):
        # Single-line comment
        script = '// This is a comment\nset_inf_attr(INF_COMPILER, 1);'
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)
        
        # Multi-line comment
        script = '/* Comment spanning\nmultiple lines */\nadd_segment(0x1000, 0x2000);'
        tree = self.parser.parse(script)
        self.assertIsNotNone(tree)
    
    def test_hex_literals(self):
        scripts = [
            'addr = 0x1000;',
            'addr = 0XABCD;',
            'addr = 0x1234ABCD;'
        ]
        for script in scripts:
            tree = self.parser.parse(script)
            self.assertIsNotNone(tree)
    
    def test_string_operations(self):
        scripts = [
            'name = "seg" + "ment";',
            'path = "C:\\\\ida\\\\scripts\\\\" + script_name;',
            'msg = "Value: " + itoa(value);'
        ]
        for script in scripts:
            tree = self.parser.parse(script)
            self.assertIsNotNone(tree)
    
    def test_type_declarations(self):
        scripts = [
            'auto i, j, k;',
            'auto func_name = "main";',
            'extern some_extern_var;'
        ]
        for script in scripts:
            tree = self.parser.parse(script)
            self.assertIsNotNone(tree)
    
    def test_complex_expressions(self):
        scripts = [
            'result = (a + b) * c - d / e;',
            'flag = (val & MASK) == EXPECTED;',
            'offset = base + (index << 2);'
        ]
        for script in scripts:
            tree = self.parser.parse(script)
            self.assertIsNotNone(tree)

if __name__ == '__main__':
    unittest.main()