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
                message_type=messages.MessageType.R,
                operation_code=query.header.operation_code,
                authoritative_answer=False,
                truncated_message=False,
                recursion_desired=query.header.recursion_desired,
                recursion_available=False,
                reserved=0,
                response_code=0 if query.header.operation_code == 0 else 4,
            ),
            questions=[
                messages.Question(
                    domain_name=query.questions[0].domain_name,
                    record_type=query.questions[0].record_type,
                    record_class=query.questions[0].record_class
                )
            ],
            answers=[
                messages.Answer(
                    domain_name=query.questions[0].domain_name,
                    record_type=query.questions[0].record_type,
                    record_class=query.questions[0].record_class,
                    ttl=60,
                    data='8.8.8.8'
                )
            ]
        )

        print('>', response)

        response.serialize(self.wfile)
