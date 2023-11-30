from socketserver import DatagramRequestHandler
from app.server import DNSServer
import app.message as messages


class DNSHandler(DatagramRequestHandler):
    server: DNSServer

    def handle(self) -> None:
        query = messages.Message.unserialize(self.rfile)

        print('<', query)

        response = messages.Message(
            header=messages.Header(
                packet_id=query.header.packet_id,
                query_response=True,
                operation_code=0,
                authoritative_answer=False,
                truncated_message=False,
                recursion_desired=False,
                recursion_available=False,
                reserved=0,
                response_code=0,
                question_count=0,
                answer_count=0,
                authority_count=0,
                additional_count=0
            )
        )

        print('>', response)

        response.serialize(self.wfile)
