import enum


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
