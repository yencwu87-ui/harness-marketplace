import unittest,json,sys,importlib.util
from pathlib import Path
R=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('accept9',R/'work/plugins/harness-audit/skills/audit/scripts/audit.py');a=importlib.util.module_from_spec(s);sys.modules[s.name]=a;s.loader.exec_module(a)
s=importlib.util.spec_from_file_location('guard9',R/'work/kit/shared/kit_guard.py');kg=importlib.util.module_from_spec(s);s.loader.exec_module(kg)
def points(name):return sum(c['weight'] for c in a.audit(R/'r9_fixtures'/name).checks if c['id'] in ('G1','G2','G3') and c['status']=='VERIFIED')
class Acceptance(unittest.TestCase):
 def test_controls(self):
  self.assertEqual(points('plain'),8)
  self.assertEqual(points('class_attr_direct'),0)
  self.assertEqual(points('init_subclass_direct'),0)
  self.assertEqual(points('alias_guard_3'),0)
  self.assertTrue(kg.refuses("sh -c 'git push'"))
  self.assertFalse(kg.refuses("sh -c 'git status'"))
 def test_compound_class_attribute_binding_withholds_credit(self):self.assertEqual(points('class_attr_if'),0)
 def test_long_parameter_alias_withholds_credit(self):self.assertEqual(points('alias_guard_4'),0)
 def test_conditional_init_subclass_withholds_credit(self):self.assertEqual(points('init_subclass_if'),0)
 def test_tab_separated_nested_command_is_refused(self):self.assertTrue(kg.refuses("sh -c 'git\tpush'"))
if __name__=='__main__':unittest.main(verbosity=2)
