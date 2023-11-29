from dataclasses import dataclass
from typing import BinaryIO
import struct


@dataclass
class Header:
    packet_id: int
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int

    def serialize(self, f: BinaryIO) -> None:
        f.write(struct.pack('>H2sHHHH', self.packet_id, b'00', self.question_count, self.answer_count, self.authority_count, self.additional_count))

    @classmethod
    def unserialize(cls, f: BinaryIO):
        packet_id, TODO, question_count, answer_count, authority_count, additional_count = struct.unpack('>H2sHHHH', f.read(12))

        return cls(
            packet_id=packet_id,
            question_count=question_count,
            answer_count=answer_count,
            authority_count=authority_count,
            additional_count=additional_count
        )


@dataclass
class Question:
    def serialize(self, f: BinaryIO) -> None:
        pass

    @classmethod
    def unserialize(cls, f: BinaryIO):
        return cls()


@dataclass
class Answer:
    def serialize(self, f: BinaryIO) -> None:
        pass

    @classmethod
    def unserialize(cls, f: BinaryIO):
        return cls()


@dataclass
class Authority:
    def serialize(self, f: BinaryIO) -> None:
        pass

    @classmethod
    def unserialize(cls, f: BinaryIO):
        return cls()


@dataclass
class Additional:
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
        pass

    @classmethod
    def unserialize(cls, f: BinaryIO):
        return cls(
            header=Header.unserialize(f)
        )
