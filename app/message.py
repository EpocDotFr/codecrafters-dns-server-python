from typing import BinaryIO, Tuple, List, Any
from socket import inet_aton, inet_ntoa
from dataclasses import dataclass
import struct
import enum


def serialize_domain_name(f: BinaryIO, domain_name: List[str]) -> None:
    f.write(b''.join([
        len(label).to_bytes(1, byteorder='big') + label.encode() for label in domain_name
    ]) + b'\x00')


def unserialize_domain_name(f: BinaryIO) -> List[str]:
    ret = []
    old_pos = None

    while True:
        char = f.read(1)

        if char == b'\x00':
            break

        label_length = int.from_bytes(char, byteorder='big')
        label_length_bits = format(label_length, '08b')

        if not old_pos and label_length_bits[:2] == '11': # Compressed label
            pointer_pos_bits = label_length_bits[2:] + format(int.from_bytes(f.read(1), byteorder='big'), '08b')
            pointer_pos = int(pointer_pos_bits, 2)

            print('pointer_pos', pointer_pos)

            old_pos = f.tell()

            f.seek(pointer_pos)
        else:
            label = f.read(label_length).decode()

            ret.append(label)

    return ret


@enum.unique
class MessageType(enum.Enum):
    Q = '0'
    R = '1'


@enum.unique
class RecordType(enum.Enum):
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
    RP = 17
    AFSDB = 18
    X25 = 19
    ISDN = 20
    RT = 21
    NSAP = 22
    NSAP_PTR = 23
    SIG = 24
    KEY = 25
    PX = 26
    GPOS = 27
    AAAA = 28
    LOC = 29
    NXT = 30
    EID = 31
    NIMLOC = 32
    SRV = 33
    ATMA = 34
    NAPTR = 35
    KX = 36
    CERT = 37
    A6 = 38
    DNAME = 39
    SINK = 40
    OPT = 41
    APL = 42
    DS = 43
    SSHFP = 44
    IPSECKEY = 45
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    DHCID = 49
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    SMIMEA = 53
    HIP = 55
    NINFO = 56
    RKEY = 57
    TALINK = 58
    CDS = 59
    CDNSKEY = 60
    OPENPGPKEY = 61
    CSYNC = 62
    ZONEMD = 63
    SVCB = 64
    HTTPS = 65
    UINFO = 100
    UID = 101
    GID = 102
    UNSPEC = 103
    NID = 104
    L32 = 105
    L64 = 106
    LP = 107
    EUI48 = 108
    EUI64 = 109
    TKEY = 249
    TSIG = 250
    IXFR = 251
    AXFR = 252
    MAILB = 253
    MAILA = 254
    STAR = 255
    URI = 256
    CAA = 257
    DOA = 259
    TA = 32768
    DLV = 32769


@enum.unique
class RecordClass(enum.Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4
    NONE = 254
    STAR = 255
    EDNS = 4096


@enum.unique
class OperationCode(enum.Enum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2
    NOTIFY = 4
    UPDATE = 5


@enum.unique
class ResponseCode(enum.Enum):
    NO_ERROR = 0
    FORM_ERR = 1
    SERV_FAIL = 2
    NX_DOMAIN = 3
    NOT_IMP = 4
    REFUSED = 5
    YX_DOMAIN = 6
    YXRR_SET = 7
    NXRR_SET = 8
    NO_AUTH = 9
    NOT_ZONE = 10
    BAD_VERS_OR_SIG = 16
    BAD_KEY = 17
    BAD_TIME = 18
    BAD_MODE = 19
    BAD_NAME = 20
    BAD_ALG = 21


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
    operation_code: OperationCode
    authoritative_answer: bool
    truncated_message: bool
    recursion_desired: bool
    recursion_available: bool
    reserved: int
    response_code: ResponseCode

    _format = 'H2s'

    def serialize(self, f: BinaryIO) -> None:
        bits = ''

        bits += self.message_type.value
        bits += format(self.operation_code.value, '04b')
        bits += '1' if self.authoritative_answer else '0'
        bits += '1' if self.truncated_message else '0'
        bits += '1' if self.recursion_desired else '0'
        bits += '1' if self.recursion_available else '0'
        bits += format(self.reserved, '03b')
        bits += format(self.response_code.value, '04b')

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
            operation_code=OperationCode(int(bits[1:5], 2)),
            authoritative_answer=bits[5] == '1',
            truncated_message=bits[6] == '1',
            recursion_desired=bits[7] == '1',
            recursion_available=bits[8] == '1',
            reserved=int(bits[9:12], 2),
            response_code=ResponseCode(int(bits[12:], 2))
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
class Record(HasStructMixin):
    domain_name: List[str]
    record_type: RecordType
    record_class: RecordClass
    ttl: int
    data: Any

    _format = 'HHIH'

    def serialize(self, f: BinaryIO) -> None:
        serialize_domain_name(f, self.domain_name)

        if self.record_class == RecordClass.IN:
            if self.record_type == RecordType.A:
                raw_data = inet_aton(self.data)
            else:
                raise NotImplementedError(f'Serialization not implemented for record type {self.record_type.name}')
        else:
            raise NotImplementedError(f'Serialization not implemented for record class {self.record_class.name}')

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

        if record_class == RecordClass.IN:
            if record_type == RecordType.A:
                data = inet_ntoa(raw_data)
            else:
                raise NotImplementedError(f'Unserialization not implemented for record type {record_type.name}')
        else:
            raise NotImplementedError(f'Unserialization not implemented for record class {record_class.name}')

        return cls(
            domain_name=domain_name,
            record_type=record_type,
            record_class=record_class,
            ttl=ttl,
            data=data
        )


@dataclass
class Message(HasStructMixin):
    header: Header
    questions: List[Question]
    answers: List[Record]
    authorities: List[Record]
    additional: List[Record]

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

        for authority in self.authorities:
            authority.serialize(f)

        for additional in self.additional:
            additional.serialize(f)

    @classmethod
    def unserialize(cls, f: BinaryIO):
        header = Header.unserialize(f)

        question_count, answer_count, authority_count, additional_count = cls.unpack(f)

        questions = [
            Question.unserialize(f) for _ in range(question_count)
        ]

        answers = [
            Record.unserialize(f) for _ in range(answer_count)
        ]

        authorities = [
            Record.unserialize(f) for _ in range(authority_count)
        ]

        additional = [
            Record.unserialize(f) for _ in range(additional_count)
        ]

        return cls(
            header=header,
            questions=questions,
            answers=answers,
            authorities=authorities,
            additional=additional
        )
