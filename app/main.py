from app.handler import DNSHandler
from app.server import DNSServer


def main() -> None:
    with DNSServer(('127.0.0.1', 2053), DNSHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
