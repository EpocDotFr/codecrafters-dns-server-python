from typing import BinaryIO, List


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

        label_length = int.from_bytes(char, byteorder='big')
        label_length_bits = format(label_length, '08b')

        if label_length_bits[:2] == '11': # Compressed label
            pointer_pos_bits = label_length_bits[2:] + format(int.from_bytes(f.read(1), byteorder='big'), '08b')
            pointer_pos = int(pointer_pos_bits, 2)

            print('pointer_pos', pointer_pos)

            # f.seek(pointer_pos)
        else:
            label = f.read(label_length).decode()

            ret.append(label)

    return ret
