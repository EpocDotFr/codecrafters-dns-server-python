from socketserver import DatagramRequestHandler
from app.server import DNSServer
import app.message as messages
import app.enums as enums


class DNSHandler(DatagramRequestHandler):
    server: DNSServer

    def handle(self) -> None:
        query = messages.Message.unserialize(self.rfile)

        print('<', query)

        response = messages.Message(
            header=messages.Header(
                packet_id=query.header.packet_id,
                message_type=enums.MessageType.R,
                operation_code=query.header.operation_code,
                authoritative_answer=False,
                truncated_message=False,
                recursion_desired=query.header.recursion_desired,
                recursion_available=False,
                reserved=0,
                response_code=enums.ResponseCode.NO_ERROR if query.header.operation_code == 0 else enums.ResponseCode.NOT_IMP,
            ),
            questions=[
                messages.Question(
                    domain_name=query.questions[0].domain_name,
                    record_type=enums.RecordType.A,
                    record_class=enums.RecordClass.IN
                )
            ],
            answers=[
                messages.Record(
                    domain_name=query.questions[0].domain_name,
                    record_type=enums.RecordType.A,
                    record_class=enums.RecordClass.IN,
                    ttl=60,
                    data='8.8.8.8'
                )
            ],
            authorities=[],
            additional=[]
        )

        print('>', response)

        response.serialize(self.wfile)
