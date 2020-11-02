from secrets import token_bytes
K = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

H = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)


def rotate_right(x, b):
    return ((x >> b) | (x << (32 - b))) & 0xFFFFFFFF





def pad(message):
    if len(message) % 64 == 0:
        return message
    padding_len = 64 - (len(message) % 64)
    padding = bytes([padding_len] * padding_len)
    return message + padding


def split_blocks(message, block_size=64):
    return [message[i:i + 64] for i in range(0, len(message), block_size)]


def sha_compress(xt, kt, a, b, c, d, e, f, g, h):
    ch = (e & f) ^ (~e & g)
    maj = (a & b) ^ (a & c) ^ (b & c)
    s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)  # Sigma 0
    s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)  # Sigma 1
    t1 = h + s1 + ch + xt + kt
    return (t1 + s0 + maj) & 0xFFFFFFFF, a, b, c, (d + t1) & 0xFFFFFFFF, e, f, g


class sha256():
    def __init__(self, message):
        self.message = pad(message)

    def hash(self):
        digest = list(H)
        for block in split_blocks(self.message):
            X = [0]*64
            X[0:16] = [int.from_bytes(block[i:i + 4], 'big') for i in range(0, 64, 4)]
            for i in range(16, 64):
                s0 = rotate_right(X[i - 15], 7) ^ rotate_right(X[i - 15], 18) ^ (X[i - 15] >> 3)
                s1 = rotate_right(X[i - 2], 17) ^ rotate_right(X[i - 2], 19) ^ (X[i - 2] >> 10)
                X[i] = (X[i - 16] + s0 + X[i - 7] + s1) & 0xFFFFFFFF
            a, b, c, d, e, f, g, h = digest
            for i in range(64):
                a, b, c, d, e, f, g, h = sha_compress(X[i], K[i], a, b, c, d, e, f, g, h)
            digest = [(x + y) & 0xFFFFFFF for x, y in zip(digest,  (a, b, c, d, e, f, g, h))]
        return b''.join(d.to_bytes(4, 'big') for d in digest)


def proof_of_work():
    while True:
        x = token_bytes(32)
        sha = sha256(x)
        hash = sha.hash()
        srt = ''.join('{:02x}'.format(i) for i in hash)
        if srt[:20] == '0'*20:
            break


if __name__ == '__main__':
    import time
    sha_obj = sha256(b'a'*64*1024)
    hash = sha_obj.hash()
    print(hash)
    print(''.join('{:02x}'.format(i) for i in hash))

    start = time.time()
    proof_of_work()
    stop = time.time()
    print(stop-start)