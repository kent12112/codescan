import unittest
from unittest.mock import Mock, patch
from egress import proxy


class ProxyRoutingTests(unittest.TestCase):
    @patch.object(proxy, 'OSV_MITM_PROXY', '127.0.0.1:8081')
    @patch.object(proxy.socket, 'create_connection', side_effect=OSError('inspector down'))
    def test_osv_never_falls_back_to_direct_tunnel(self, connect):
        client = Mock()
        client.recv.return_value = b'CONNECT api.osv.dev:443 HTTP/1.1\r\n\r\n'
        proxy.handle(client)
        connect.assert_called_once_with(('127.0.0.1', 8081), timeout=10)
        self.assertTrue(client.sendall.call_args.args[0].startswith(b'HTTP/1.1 502'))

    @patch.object(proxy, 'OSV_MITM_PROXY', '127.0.0.1:8081')
    @patch.object(proxy, '_pipe')
    @patch.object(proxy.socket, 'create_connection')
    def test_anthropic_stays_a_direct_tls_tunnel(self, connect, pipe):
        client = Mock()
        client.recv.return_value = b'CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n'
        proxy.handle(client)
        connect.assert_called_once_with(('api.anthropic.com', 443), timeout=10)
        pipe.assert_called_once()

    @patch.object(proxy.socket, 'create_connection')
    def test_unapproved_destination_never_connects(self, connect):
        client = Mock()
        client.recv.return_value = b'CONNECT example.com:443 HTTP/1.1\r\n\r\n'
        proxy.handle(client)
        connect.assert_not_called()
        self.assertTrue(client.sendall.call_args.args[0].startswith(b'HTTP/1.1 403'))
