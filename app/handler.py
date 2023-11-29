from socketserver import DatagramRequestHandler
from app.server import DNSServer


class DNSHandler(DatagramRequestHandler):
    server: DNSServer

    def handle(self) -> None:
        print(self.rfile.read(512))

        self.wfile.write(b'')
