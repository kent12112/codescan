"""Minimal egress proxy: allowlist outbound HTTPS by destination host.

Clients tunnel HTTPS through a forward proxy with an HTTP CONNECT request, which
names the destination host. We allow hosts on the allowlist (open a raw tunnel,
no TLS decryption) and refuse everything else. With OSV_MITM_PROXY configured,
OSV is routed through a local inspection listener. Other hosts remain tunneled.
"""
import socket
import threading
import os

# The analyst keeps its narrow default; the scanner proxy has a separate list.
ALLOWLIST = set(os.environ.get("EGRESS_HOSTS", "api.anthropic.com,api.osv.dev").split(","))
LISTEN = (os.environ.get('EGRESS_BIND', '0.0.0.0'), int(os.environ.get('EGRESS_PORT', '8080')))
OSV_MITM_PROXY = os.environ.get("OSV_MITM_PROXY")


def handle(client):
    upstream = None
    try:
        client.settimeout(10)
        headers = b''
        while b'\r\n\r\n' not in headers and len(headers) < 8192:
            chunk = client.recv(min(4096, 8192-len(headers)))
            if not chunk:
                raise ConnectionError('incomplete proxy request')
            headers += chunk
        if not headers.endswith(b'\r\n\r\n'):
            raise ValueError('invalid proxy headers')
        line = headers.split(b"\r\n", 1)[0].decode('ascii')
        parts = line.split()                      # "CONNECT api.osv.dev:443 HTTP/1.1"
        if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] != 'HTTP/1.1':
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        host, _, port = parts[1].partition(":")
        port = int(port or 443)

        if host not in ALLOWLIST or port != 443:
            print("  [EGRESS BLOCKED] destination or port", flush=True)
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nblocked by egress allowlist")
            return

        print(f"  [EGRESS ALLOWED] {host}:{port}")
        if host == 'api.osv.dev' and OSV_MITM_PROXY:
            proxy_host, proxy_port = OSV_MITM_PROXY.rsplit(':', 1)
            upstream = socket.create_connection((proxy_host, int(proxy_port)), timeout=10)
            upstream.sendall(b'CONNECT api.osv.dev:443 HTTP/1.1\r\nHost: api.osv.dev:443\r\n\r\n')
            response = b''
            while b'\r\n\r\n' not in response and len(response) < 8192:
                chunk = upstream.recv(1024)
                if not chunk:
                    raise ConnectionError('inspection listener closed')
                response += chunk
            if not response.startswith(b'HTTP/1.1 200 ') or not response.endswith(b'\r\n\r\n'):
                raise ConnectionError('inspection listener refused tunnel')
        else:
            upstream = socket.create_connection((host, port), timeout=10)
        # Model generation can take longer than the connection-establishment budget.
        upstream.settimeout(180)
        client.settimeout(180)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        _pipe(client, upstream)
    except Exception:
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception:
            pass
    finally:
        client.close()
        if upstream is not None:
            upstream.close()


def _pipe(a, b):
    def fwd(src, dst):
        try:
            while True:
                data = src.recv(8192)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
    t1 = threading.Thread(target=fwd, args=(a, b), daemon=True)
    t2 = threading.Thread(target=fwd, args=(b, a), daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN); srv.listen(50)
    print(f"egress proxy on {LISTEN[0]}:{LISTEN[1]}, allowlist={sorted(ALLOWLIST)}")
    slots = threading.BoundedSemaphore(32)
    def serve(client):
        try:
            handle(client)
        finally:
            slots.release()
    while True:
        client, _ = srv.accept()
        if not slots.acquire(blocking=False):
            client.close()
            continue
        threading.Thread(target=serve, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
