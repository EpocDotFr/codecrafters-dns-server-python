from typing import BinaryIO, Tuple, List, Any
from dataclasses import dataclass, field
from socket import inet_aton, inet_ntoa
from enum import Enum
import struct


def serialize_domain_name(f: BinaryIO, domain_name: List[str]) -> None:
    f.write(b''.join([
        len(label).to_bytes(1, byteorder='big') + label.encode() for label in domain_name
    ]) + b'\x00')


def unserialize_domain_name(f: BinaryIO) -> List[str]:
    ret = []

    while True:
        char = f.read(1)

        if char == b'\x00':
            break

        label = f.read(
            int.from_bytes(char, byteorder='big')
        ).decode()

        ret.append(label)

    return ret


class MessageType(Enum):
    Q = '0'
    R = '1'


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
    AXFR = 252
    MAILB = 253
    MAILA = 254
    STAR = 255


class RecordClass(Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4
    STAR = 255


class HasStructMixin:
    _format: str

    def pack(self, f: BinaryIO, *data) -> None:
        f.write(struct.pack(f'>{self._format}', *data))

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

    _format = 'H2s'

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

        self.pack(
            f,
            self.packet_id,
            int(bits, 2).to_bytes(2, byteorder='big')
        )

    @classmethod
    def unserialize(cls, f: BinaryIO):
        packet_id, bits = cls.unpack(f)

        bits = ''.join([format(b, '08b') for b in bits])

        return cls(
            packet_id=packet_id,
            message_type=MessageType(bits[0]),
            operation_code=int(bits[1:5], 2),
            authoritative_answer=bits[5] == '1',
            truncated_message=bits[6] == '1',
            recursion_desired=bits[7] == '1',
            recursion_available=bits[8] == '1',
            reserved=int(bits[9:12], 2),
            response_code=int(bits[12:], 2)
        )


@dataclass
class Question(HasStructMixin):
    domain_name: List[str]
    record_type: RecordType
    record_class: RecordClass

    _format = 'HH'

    def serialize(self, f: BinaryIO) -> None:
        serialize_domain_name(f, self.domain_name)

        self.pack(
            f,
            self.record_type.value,
            self.record_class.value
        )

    @classmethod
    def unserialize(cls, f: BinaryIO):
        domain_name = unserialize_domain_name(f)

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
    domain_name: List[str]
    record_type: RecordType
    record_class: RecordClass
    ttl: int
    data: Any

    _format = 'HHIH'

    def serialize(self, f: BinaryIO) -> None:
        serialize_domain_name(f, self.domain_name)

        if self.record_type == RecordType.A:
            raw_data = inet_aton(self.data)
        else:
            raise NotImplementedError(f'Answer serialization Not implemented for record type {self.record_type.name}')

        self.pack(
            f,
            self.record_type.value,
            self.record_class.value,
            self.ttl,
            len(raw_data)
        )

        f.write(raw_data)

    @classmethod
    def unserialize(cls, f: BinaryIO):
        domain_name = unserialize_domain_name(f)

        record_type, record_class, ttl, raw_data_length = cls.unpack(f)

        record_type = RecordType(record_type)
        record_class = RecordClass(record_class)

        raw_data = f.read(raw_data_length)

        if record_type == RecordType.A:
            data = inet_ntoa(raw_data)
        else:
            raise NotImplementedError(f'Answer unserialization not implemented for record type {record_type.name}')

        return cls(
            domain_name=domain_name,
            record_type=record_type,
            record_class=record_class,
            ttl=ttl,
            data=data
        )


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
class Message(HasStructMixin):
    header: Header
    questions: List[Question]
    answers: List[Answer]
    authorities: List[Authority] = field(default_factory=list) # TODO
    additional: List[Additional] = field(default_factory=list) # TODO

    _format = 'HHHH'

    def serialize(self, f: BinaryIO) -> None:
        self.header.serialize(f)

        self.pack(
            f,
            len(self.questions),
            len(self.answers),
            len(self.authorities),
            len(self.additional)
        )

        for question in self.questions:
            question.serialize(f)

        for answer in self.answers:
            answer.serialize(f)

    @classmethod
    def unserialize(cls, f: BinaryIO):
        header = Header.unserialize(f)

        question_count, answer_count, authority_count, additional_count = cls.unpack(f)

        questions = [
            Question.unserialize(f) for _ in range(question_count)
        ]

        answers = [
            Answer.unserialize(f) for _ in range(answer_count)
        ]

        return cls(
            header=header,
            questions=questions,
            answers=answers
        )
