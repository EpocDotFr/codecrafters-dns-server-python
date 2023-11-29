from socketserver import DatagramRequestHandler
from app.server import DNSServer
from app.message import Message


class DNSHandler(DatagramRequestHandler):
    server: DNSServer

    def handle(self) -> None:
        message = Message.unserialize(self.rfile)

        print(message)

        self.wfile.write(b'')
