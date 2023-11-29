from socketserver import ThreadingUDPServer


class DNSServer(ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True
