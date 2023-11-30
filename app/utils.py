def byte_to_bits(b: bytes) -> str:
    return format(int.from_bytes(b, byteorder='big'), '08b')


def bits_to_byte(b: str) -> bytes:
    return int(b, 2).to_bytes(4, byteorder='big')
