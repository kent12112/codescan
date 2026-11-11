import json
import os
from pathlib import Path
import tempfile
import unittest
from codescan.synthesize import _validate_merged, _recover_dropped
from tools.reports import extract_report, save_and_render, safe_text


class ReportTests(unittest.TestCase):
    def test_model_cannot_invent_cross_tool_corroboration(self):
        raw=[{'tool':'semgrep','severity':'HIGH'}]
        merged=[{'title':'test','summary':'test','severity':'HIGH','sources_idx':[0],
                 'sources':['semgrep','llm-agent'],'confidence':'confirmed'}]
        result=_validate_merged(merged,raw)
        self.assertEqual(result[0]['confidence'],'single-source')
        self.assertEqual(result[0]['sources'],['semgrep'])

    def test_all_raw_severities_are_recovered_if_dropped(self):
        raw=[{'tool':'semgrep','severity':'MEDIUM','title':'test','message':'evidence'}]
        result=_recover_dropped(raw,[])
        self.assertEqual(result[0]['severity'],'MEDIUM')

    def test_out_of_range_or_duplicate_evidence_fails(self):
        raw=[{'tool':'semgrep','severity':'HIGH'}]
        for indices in [[True], [2], [0,0]]:
            with self.assertRaises(ValueError):
                _validate_merged([{'title':'x','summary':'x','severity':'HIGH','sources_idx':indices}],raw)

    def test_duplicate_or_missing_report_is_not_a_success(self):
        for logs in ['', 'CODESCAN_REPORT={}\nCODESCAN_REPORT={}']:
            with self.assertRaises(ValueError): extract_report(logs)

    def test_report_is_private_and_console_controls_are_removed(self):
        data={'schema_version':1,'findings':[{'title':'test\x1b[31m','summary':'evidence',
              'severity':'HIGH','confidence':'single-source','sources':['semgrep']}]}
        parsed=extract_report('progress\nCODESCAN_REPORT='+json.dumps(data))
        with tempfile.TemporaryDirectory() as directory:
            path=save_and_render(parsed,'test',Path(directory)/'reports')
            self.assertEqual(os.stat(path).st_mode & 0o777,0o600)
        self.assertNotIn('\x1b',safe_text(data['findings'][0]['title']))
