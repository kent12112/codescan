"""Minimal egress proxy: allowlist outbound HTTPS by destination host.

Clients tunnel HTTPS through a forward proxy with an HTTP CONNECT request, which
names the destination host. We allow hosts on the allowlist (open a raw tunnel,
no TLS decryption — 'path B') and refuse everything else. Destination-level
control; body inspection would require TLS termination (the advanced version).
"""
import socket
import threading

ALLOWLIST = {"api.anthropic.com", "api.osv.dev"}
LISTEN = ("0.0.0.0", 8080)


def handle(client):
    try:
        line = client.recv(4096).split(b"\r\n", 1)[0].decode(errors="ignore")
        parts = line.split()                      # "CONNECT api.osv.dev:443 HTTP/1.1"
        if len(parts) < 2 or parts[0] != "CONNECT":
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        host, _, port = parts[1].partition(":")
        port = int(port or 443)

        if host not in ALLOWLIST:
            print(f"  [EGRESS BLOCKED] {host}:{port}")
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nblocked by egress allowlist")
            return

        print(f"  [EGRESS ALLOWED] {host}:{port}")
        upstream = socket.create_connection((host, port), timeout=10)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        _pipe(client, upstream)
    except Exception:
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception:
            pass
    finally:
        client.close()


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
    t1 = threading.Thread(target=fwd, args=(a, b), daemon=True)
    t2 = threading.Thread(target=fwd, args=(b, a), daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN); srv.listen(50)
    print(f"egress proxy on {LISTEN[0]}:{LISTEN[1]}, allowlist={sorted(ALLOWLIST)}")
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
