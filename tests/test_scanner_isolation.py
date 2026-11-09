import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from codescan.workspace import throwaway_copy
from codescan.semgrep_scan import run_semgrep
from egress.scanner_entry import unpack, wait_for_isolation
from tools.scan_job import bundle_source, make_job
from tools.scan_job import main as launch_scan


class IsolationTests(unittest.TestCase):
    @patch('egress.scanner_entry.time.sleep')
    @patch('egress.scanner_entry.socket.create_connection')
    def test_missing_network_enforcement_refuses_to_start(self, connect, sleep):
        with self.assertRaisesRegex(RuntimeError, 'refusing to read scan input'):
            wait_for_isolation()
        self.assertTrue(connect.called)

    @patch('egress.scanner_entry.socket.create_connection', side_effect=OSError('denied'))
    def test_network_guard_accepts_blocked_connections(self, connect):
        wait_for_isolation()
        self.assertEqual(connect.call_count, 2)

    def test_local_bundle_excludes_links_credentials_and_generated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app.py').write_text('print(1)')
            (root / '.env').write_text('SECRET=private')
            (root / 'link.py').symlink_to('/etc/passwd')
            (root / '.git').mkdir()
            (root / '.git' / 'config').write_text('private')
            (root / 'node_modules').mkdir()
            (root / 'node_modules' / 'junk').write_text('junk')
            bundle = bundle_source(root)
            with tarfile.open(fileobj=io.BytesIO(bundle), mode='r:gz') as archive:
                self.assertEqual(archive.getnames(), ['app.py'])
            with tempfile.TemporaryDirectory() as destination:
                archive_path = root / 'bundle.tar.gz'
                archive_path.write_bytes(bundle)
                unpack(archive_path, destination)
                self.assertEqual((Path(destination) / 'app.py').read_text(), 'print(1)')

    def test_archive_rejects_escape_and_links(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE),
                           ('link', tarfile.SYMTYPE), ('device', tarfile.CHRTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with tarfile.open(root / 'bad.tar.gz', 'w:gz') as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = '/etc/passwd'
                    archive.addfile(member)
                with self.assertRaises(ValueError):
                    unpack(root / 'bad.tar.gz', root / 'output')

    def test_remote_checkout_copy_never_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app.py').write_text('print(1)')
            (root / 'leak.py').symlink_to('/etc/passwd')
            with throwaway_copy(root) as copy:
                self.assertFalse((copy / 'leak.py').exists())
                self.assertTrue((copy / 'app.py').exists())

    def test_job_has_no_cluster_token_or_host_mount_and_bounded_resources(self):
        job = make_job('test', '/input/source', {'repo.tar.gz': b'data'})
        spec = job['spec']['template']['spec']
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertFalse(any('hostPath' in volume for volume in spec['volumes']))
        container = spec['containers'][0]
        self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
        self.assertEqual(container['securityContext']['capabilities']['drop'], ['ALL'])
        self.assertTrue(container['resources']['limits']['memory'])
        self.assertTrue(container['volumeMounts'][1]['readOnly'])
        self.assertEqual(container['env'][1]['valueFrom']['secretKeyRef']['name'], 'anthropic')

    @patch.dict('os.environ', {'STRICT_SCAN': '1'})
    @patch('codescan.semgrep_scan.subprocess.run')
    def test_scanner_failure_cannot_be_reported_as_clean(self, run):
        run.return_value.stdout = json.dumps({'results': [], 'errors': [{'message': 'failed'}]})
        run.return_value.returncode = 2
        with self.assertRaises(RuntimeError):
            run_semgrep('/tmp/target')

    @patch('tools.scan_job.kubectl')
    def test_failed_job_returns_failure_and_cleans_input(self, command):
        def response(*args, **kwargs):
            from subprocess import CompletedProcess
            if args[:2] == ('get', 'job'):
                output = {'status': {'failed': 1}}
            else:
                output = {'metadata': {'uid': 'test-uid'}}
            return CompletedProcess(args, 0, stdout=json.dumps(output))
        command.side_effect = response
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'app.py').write_text('print(1)')
            with patch('sys.argv', ['scan_job.py', directory]):
                with self.assertRaisesRegex(RuntimeError, 'scanner Job failed'):
                    launch_scan()
        calls = [call.args for call in command.call_args_list]
        self.assertTrue(any(args[:2] == ('delete', 'job') for args in calls))
        self.assertTrue(any(args[:2] == ('delete', 'configmap') for args in calls))
        self.assertFalse(any(args[:2] == ('get', 'secret') for args in calls))


if __name__ == '__main__':
    unittest.main()
