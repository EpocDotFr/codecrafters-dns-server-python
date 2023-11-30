from typing import BinaryIO, Tuple, List
from dataclasses import dataclass
from enum import Enum
import struct


class MessageType(Enum):
    Query = '0'
    Response = '1'


class RecordType(Enum):
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16


class RecordClass(Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4


class HasStructMixin:
    _format: str

    def pack(self, *data) -> bytes:
        return struct.pack(f'>{self._format}', *data)

    @classmethod
    def unpack(cls, f: BinaryIO) -> Tuple:
        return struct.unpack(f'>{cls._format}', f.read(cls.size()))

    @classmethod
    def size(cls) -> int:
        return struct.calcsize(cls._format)


@dataclass
class Header(HasStructMixin):
    packet_id: int
    message_type: MessageType
    operation_code: int
    authoritative_answer: bool
    truncated_message: bool
    recursion_desired: bool
    recursion_available: bool
    reserved: int
    response_code: int
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int

    _format = 'H2sHHHH'

    def serialize(self, f: BinaryIO) -> None:
        bits = ''

        bits += self.message_type.value
        bits += format(self.operation_code, '04b')
        bits += '1' if self.authoritative_answer else '0'
        bits += '1' if self.truncated_message else '0'
        bits += '1' if self.recursion_desired else '0'
        bits += '1' if self.recursion_available else '0'
        bits += format(self.reserved, '03b')
        bits += format(self.response_code, '04b')

        bits = int(bits, 2).to_bytes(2, byteorder='big')

        f.write(self.pack(
            self.packet_id,
            bits,
            self.question_count,
            self.answer_count,
            self.authority_count,
            self.additional_count
        ))

    @classmethod
    def unserialize(cls, f: BinaryIO):
        packet_id, bits, question_count, answer_count, authority_count, additional_count = cls.unpack(f)

        bits = ''.join([format(b, '08b') for b in bits])

        return cls(
            packet_id=packet_id,
            message_type=MessageType(bits[0]),
            operation_code=int(bits[1::4], 2),
            authoritative_answer=bits[6] == '1',
            truncated_message=bits[7] == '1',
            recursion_desired=bits[8] == '1',
            recursion_available=bits[9] == '1',
            reserved=int(bits[10::3], 2),
            response_code=int(bits[14::4], 2),
            question_count=question_count,
            answer_count=answer_count,
            authority_count=authority_count,
            additional_count=additional_count
        )


@dataclass
class Question(HasStructMixin):
    domain_name: List[str]
    record_type: RecordType
    record_class: RecordClass

    _format = 'HH'

    def serialize(self, f: BinaryIO) -> None:
        f.write(b''.join([
            len(label).to_bytes(2) + label.encode() for label in self.domain_name
        ]) + b'\x00')

        f.write(self.pack(
            self.record_type.value,
            self.record_class.value
        ))

    @classmethod
    def unserialize(cls, f: BinaryIO):
        domain_name = []

        while True:
            char = f.read(1)

            if char == b'\x00':
                break

            label = f.read(
                int.from_bytes(char, byteorder='big')
            ).decode()

            domain_name.append(label)

        record_type, record_class = cls.unpack(f)

        record_type = RecordType(record_type)
        record_class = RecordClass(record_class)

        return cls(
            domain_name=domain_name,
            record_type=record_type,
            record_class=record_class
        )


@dataclass
class Answer(HasStructMixin):
    def serialize(self, f: BinaryIO) -> None:
        pass

    @classmethod
    def unserialize(cls, f: BinaryIO):
        return cls()


@dataclass
class Authority(HasStructMixin):
    def serialize(self, f: BinaryIO) -> None:
        pass

    @classmethod
    def unserialize(cls, f: BinaryIO):
        return cls()


@dataclass
class Additional(HasStructMixin):
    def serialize(self, f: BinaryIO) -> None:
        pass

    @classmethod
    def unserialize(cls, f: BinaryIO):
        return cls()


@dataclass
class Message:
    header: Header
    questions: List[Question]
    # answers: List[Answer]
    # authorities: List[Authority]
    # additional: List[Additional]

    def serialize(self, f: BinaryIO) -> None:
        self.header.serialize(f)

        for question in self.questions:
            question.serialize(f)

    @classmethod
    def unserialize(cls, f: BinaryIO):
        header = Header.unserialize(f)

        questions = [
            Question.unserialize(f) for _ in range(header.question_count)
        ]

        return cls(
            header=header,
            questions=questions
        )
