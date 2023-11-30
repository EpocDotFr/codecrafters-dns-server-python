from typing import BinaryIO, Tuple, Any
from app.utils import byte_to_bits
from dataclasses import dataclass
import struct


class HasStructMixin:
    _format: str

    def pack(self, *data) -> bytes:
        return struct.pack(f'>{self._format}', *data)

    @classmethod
    def unpack(cls, data: bytes) -> Tuple:
        return struct.unpack(f'>{cls._format}', data)

    @classmethod
    def size(cls) -> int:
        return struct.calcsize(cls._format)


@dataclass
class Header(HasStructMixin):
    packet_id: int
    query_response: bool
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
        f.write(self.pack(
            self.packet_id,
            b'00',
            self.question_count,
            self.answer_count,
            self.authority_count,
            self.additional_count
        ))

    @classmethod
    def unserialize(cls, f: BinaryIO):
        packet_id, bits, question_count, answer_count, authority_count, additional_count = cls.unpack(f.read(cls.size()))

        bits = ''.join([byte_to_bits(b) for b in bits])

        print(bits)

        return cls(
            packet_id=packet_id,
            query_response=bits[0] == '1',
            operation_code=int(bits[1:4], 2),
            authoritative_answer=bits[6] == '1',
            truncated_message=bits[7] == '1',
            recursion_desired=bits[8] == '1',
            recursion_available=bits[9] == '1',
            reserved=int(bits[10:3], 2),
            response_code=int(bits[14:4], 2),
            question_count=question_count,
            answer_count=answer_count,
            authority_count=authority_count,
            additional_count=additional_count
        )


@dataclass
class Question(HasStructMixin):
    def serialize(self, f: BinaryIO) -> None:
        pass

    @classmethod
    def unserialize(cls, f: BinaryIO):
        return cls()


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
    # question: Question
    # answer: Answer
    # authority: Authority
    # additional: Additional

    def serialize(self, f: BinaryIO) -> None:
        self.header.serialize(f)

    @classmethod
    def unserialize(cls, f: BinaryIO):
        return cls(
            header=Header.unserialize(f)
        )
