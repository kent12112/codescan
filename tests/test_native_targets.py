import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from codescan.native_semgrep import targets, run


class NativeTargetsTests(unittest.TestCase):
    def test_languages_and_generic_rules_cover_text_but_not_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'app.py').write_text('print(1)')
            (root/'notes.txt').write_text('example')
            (root/'link.py').symlink_to(root/'app.py')
            (root/'.git').mkdir()
            (root/'.git'/'hidden.py').write_text('hidden')
            plan = targets(root)
            self.assertEqual(plan[0], 'Targets')
            pairs = {(item[1]['path']['ppath'], item[1]['analyzer']) for item in plan[1]}
            self.assertEqual(pairs, {('/app.py','python'),('/app.py','generic'),('/app.py','regex'),
                                     ('/notes.txt','generic'),('/notes.txt','regex')})

    def test_oversized_source_and_engine_errors_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'app.py').write_bytes(b'x'*(1024*1024+1))
            with self.assertRaises(RuntimeError): targets(root)
            (root/'app.py').write_text('print(1)')
            with patch('codescan.native_semgrep.subprocess.run') as process:
                process.return_value.stdout = json.dumps({'results': [], 'errors': [{'type':'Timeout'}]})
                process.return_value.returncode = 0
                with self.assertRaises(RuntimeError): run(root, '/missing/rules.yaml')
