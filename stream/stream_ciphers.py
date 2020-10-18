

def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


class RC4:
    def __init__(self, master_key):
        self.S = self.key_scheduling(master_key)
        self.K = self.keystream_generator(self.S)

    def key_scheduling(self, key):
        keylength = len(key)
        S = [i for i in range(256)]
        j = 0

        for i in range(256):
            j = (j + S[i] + key[i % keylength]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    def keystream_generator(self, S):
        i = 0
        j = 0

        while True:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            t = (S[i] + S[j]) % 256
            K = S[t]
            yield K

    def encrypt(self, plaintext):
        return xor_bytes(plaintext, self.K)

    def decrypt(self, ciphertext):
        return xor_bytes(ciphertext, self.K)

    def encrypt_file(self, inputf, outputf=None, chunksize = 64*1028):
        if not outputf:
            outputf = inputf + ".enc"
        with open(inputf, 'rb') as f, open(outputf, 'wb') as g:
            while True:
                chunk = f.read(chunksize)
                if len(chunk) == 0:
                    break
                enc = self.encrypt(chunk)
                g.write(enc)

    def decrypt_file(self, inputf, outputf=None, chunksize = 64*1028):
        if not outputf:
            outputf = "decrypted-" + inputf.split(".enc")[0]
        with open(inputf, 'rb') as f, open(outputf, 'wb') as g:
            while True:
                chunk = f.read(chunksize)
                if len(chunk) == 0:
                    break
                dec = self.decrypt(chunk)
                g.write(dec)


import time
if __name__ == '__main__':
    master_k = b'k'*40
    plaintext = b'M'*64*1024

    start = time.time()
    rc4_obj = RC4(master_k)
    ciphertext = rc4_obj.encrypt(plaintext)
    stop1 = time.time()
    rc4_obj = RC4(master_k)  # 'rewinding' generator
    decrypted = rc4_obj.decrypt(ciphertext)
    stop2 = time.time()
    if plaintext == decrypted:
        print('***RC4*** 64*1024 bytes encrypted in {}; decrypted in {}'.format(stop1 - start, stop2 - stop1))

    # start = time.time()
    # rc4_obj = RC4(master_k)
    # inputf = 'lorem-ipsum.txt'
    # outputf = 'rc4-test-lorem.txt.enc'
    # rc4_obj.encrypt_file(inputf, outputf)
    # stop1 = time.time()
    # rc4_obj = RC4(master_k)
    # rc4_obj.decrypt_file(outputf)
    # stop2 = time.time()
    # print('encrypted : {}, decrypted: {}'.format(stop1 - start, stop2 - stop1))

