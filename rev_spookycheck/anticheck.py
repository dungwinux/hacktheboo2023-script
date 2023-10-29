KEY = b'SUP3RS3CR3TK3Y'
CHECK = bytearray(b'\xe9\xef\xc0V\x8d\x8a\x05\xbe\x8ek\xd9yX\x8b\x89\xd3\x8c\xfa\xdexu\xbe\xdf1\xde\xb6\\')


def txfm(seq: list[int]):
    [
        (
            (
                ((f + 24) & 0xFF) ^ KEY[i % len(KEY)]
            ) - 74
        ) & 0xFF
    for i, f in enumerate(seq)]

def anti_txfm(seq: list[int]):
    return [((((x + 74) & 0xFF) ^ KEY[i % len(KEY)]) - 24) & 0xFF for i, x in enumerate(seq)]

print(bytes(anti_txfm(CHECK)))
