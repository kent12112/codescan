import unittest
from unittest.mock import patch
from legacy.mitm_waf import setup_egress_ca


class CASetupTests(unittest.TestCase):
    @patch.object(setup_egress_ca, 'run')
    @patch.object(setup_egress_ca, 'exists', return_value=True)
    def test_existing_ca_is_never_rotated(self, exists, run):
        setup_egress_ca.main()
        run.assert_not_called()

    @patch.object(setup_egress_ca, 'run')
    @patch.object(setup_egress_ca, 'exists', side_effect=[True, False])
    def test_partial_setup_fails_without_replacing_signing_key(self, exists, run):
        with self.assertRaisesRegex(RuntimeError, 'Incomplete CA setup'):
            setup_egress_ca.main()
        run.assert_not_called()
