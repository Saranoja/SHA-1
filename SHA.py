# SHA-1 or SHA1 is a one-way hash function; it computes a 160-bit message digest.
# SHA-1 often appears in security protocols; for example, many HTTPS websites use RSA with SHA-1 to secure their connections.
# SHA-1 has known weaknesses. Theoretical attacks may find a collision after 2^52 operations, or perhaps fewer.
# Resource for algorithm's steps: https://www.youtube.com/watch?v=kmHojGMUn0Q&t=2s

import hashlib


def split_and_get_ascii(plaintext):
    return [ord(c) for c in plaintext]


def convert_ascii_to_binary(
        ascii_arr):  # this converts all the ascii values in the array + pads them with 0's until reaching 8 bits
    binary_arr = []
    for number in range(0, len(ascii_arr)):
        binary_arr.append(bin(ascii_arr[number])[2:].zfill(8))
    return binary_arr


def join_all_binaries(binaries_arr):  # join all binary values and append a '1' at the end
    joined_binaries = ''
    for bin in binaries_arr:
        joined_binaries += bin
    joined_binaries += '1'
    return joined_binaries


def pad_until_512_mod_448(arr):
    while len(arr) % 512 != 448:
        arr += '0'
    return arr


# take what join_all_binaries returns but without the last digit, get its length in binary and pad with 0's at front until it gets 64 chars long
def get_64_chars(joined_binaries):
    return bin(len(joined_binaries) - 1)[2:].zfill(64)


# append the 64 characters to the previously created binary message from pad_until_512_mod_448
def merge_448_and_64(joined_binaries, chars_64):
    result = joined_binaries + chars_64
    return result


# get 512 bits chunks from the above string (since its length is 0 mod 512)
def get_512_bits_chunks(whole_string):
    return [whole_string[i:i + 512] for i in range(0, len(whole_string), 512)]


# break each chunk into a subarray of 16 32-bit 'words'
def break_chunk(chunk):
    return [chunk[i:i + 32] for i in range(0, len(chunk), 32)]


def left_rotation(n, d, nr_of_bits):
    return (n << d) | (n >> (nr_of_bits - d))


# loop through each chunk array and extend each 'small-chunk' (32 bits) to 80 bits using some standard bitwise operations
# then rotate left
def extend_32_chunk(chunk_lines):
    for chunk_line in chunk_lines:
        for i in range(16, 80):
            rotated_xor = left_rotation(chunk_line[i - 3] ^ chunk_line[i - 8] ^ chunk_line[i - 14] ^ chunk_line[i - 16],
                                        1, 32)
            if rotated_xor > 4294967295:  # that is 32 1's in binary
                rotated_xor = rotated_xor & 4294967295  # taking first 32 bits
            chunk_line.append(rotated_xor)
    return chunk_lines


def convert_lines_to_int(matrix):
    new_matrix = []
    for array in matrix:
        new_array = []
        for element in array:
            new_array.append(int(element, 2))
        new_matrix.append(new_array)
    return new_matrix


def convert_lines_to_bin(matrix):
    new_matrix = []
    for array in matrix:
        new_array = []
        for element in array:
            new_array.append(bin(element)[2:].zfill(32))
        new_matrix.append(new_array)
    return new_matrix


# bitwise standard operations
def init_constants(chunk_lines):
    MASK = 2 ** 32 - 1
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    for i in range(0, len(chunk_lines)):
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        for t in range(80):
            if t <= 19:
                K = 0x5a827999
                f = (b & c) | ((~b) & d)
            elif t <= 39:
                K = 0x6ed9eba1
                f = b ^ c ^ d
            elif t <= 59:
                K = 0x8f1bbcdc
                f = (b & c) | (b & d) | (c & d)
            else:
                K = 0xca62c1d6
                f = b ^ c ^ d

            f = f & MASK
            T = (left_rotation(a, 5, 32) + f + e + K + chunk_lines[i][t])
            e = d
            d = c
            c = left_rotation(b, 30, 32) & MASK
            b = a
            a = T
            a = a & MASK
            b = b & MASK
            c = c & MASK
            d = d & MASK
            e = e & MASK
        h0 = (h0 + a) & MASK
        h1 = (h1 + b) & MASK
        h2 = (h2 + c) & MASK
        h3 = (h3 + d) & MASK
        h4 = (h4 + e) & MASK
    return hex((h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4)


def sha(plaintext):
    binaries = convert_ascii_to_binary(split_and_get_ascii(plaintext))
    all_chunks = []
    for chunk in get_512_bits_chunks(merge_448_and_64(pad_until_512_mod_448(join_all_binaries(binaries)),
                                                      get_64_chars(join_all_binaries(binaries)))):
        all_chunks.append(break_chunk(chunk))
    all_chunks = convert_lines_to_int(all_chunks)
    extended_chunks = extend_32_chunk(all_chunks)
    bin_chunks = convert_lines_to_bin(extended_chunks)
    return (init_constants(extended_chunks))


# compute the Hamming distance for two binaries
def hamming(string1, string2):
    hamming = 0
    for i in range(0, 160):
        if string1[i] != string2[i]:
            hamming += 1
    return hamming


def solve():
    print("----------- algorithm's steps -----------")
    plaintext = 'Python is the easiest programming language'
    print('Plaintext: ', plaintext, ' -----> Ascii: ', split_and_get_ascii(plaintext))
    binaries = convert_ascii_to_binary(split_and_get_ascii(plaintext))
    print('Characters in binary: ', binaries)
    print('Joined binaries + char(1): ', join_all_binaries(binaries))
    print('Padded text until reaching a length 512 mod 448: ', pad_until_512_mod_448(join_all_binaries(binaries)))
    # print('Length for this: ', len(pad_until_512_mod_448(join_all_binaries(binaries))))
    print('64 chars after padding with 0: ', get_64_chars(join_all_binaries(binaries)))
    print('Result after merging the two strings from above: ',
          merge_448_and_64(pad_until_512_mod_448(join_all_binaries(binaries)),
                           get_64_chars(join_all_binaries(binaries))))
    print('512 bits chunks: ', get_512_bits_chunks(merge_448_and_64(pad_until_512_mod_448(join_all_binaries(binaries)),
                                                                    get_64_chars(join_all_binaries(binaries)))))
    all_chunks = []
    for chunk in get_512_bits_chunks(merge_448_and_64(pad_until_512_mod_448(join_all_binaries(binaries)),
                                                      get_64_chars(join_all_binaries(binaries)))):
        print('32-bit words for this chunk: ', break_chunk(chunk))
        all_chunks.append(break_chunk(chunk))
    all_chunks = convert_lines_to_int(all_chunks)
    extended_chunks = extend_32_chunk(all_chunks)
    bin_chunks = convert_lines_to_bin(extended_chunks)
    print('Extended chunks: ', bin_chunks)
    print('Result: ', init_constants(extended_chunks))


def main():
    print('----------- implemented algorithm results -----------')
    plaintext = 'Python is the easiest programming language'
    print('Plaintext: ', plaintext, ' -----> ', sha(plaintext))


def test_avalanche(text1, text2):
    print('----------- testing avalanche -----------')
    hash1 = sha(text1)
    hash2 = sha(text2)
    # hash1 = bin(int(hash1, 16))[2:].zfill(160)  # convert to binary
    # hash2 = bin(int(hash2, 16))[2:].zfill(160)
    print('Sha-1 result for *', text1, ' -----> ', hash1)
    print('Sha-1 result for *', text2, ' -----> ', hash2)
    print("Hashes' Hamming distance: ", hamming(bin(int(hash1, 16))[2:].zfill(160), bin(int(hash2, 16))[2:].zfill(160)))


def unit_test():
    h = hashlib.sha1()
    print('----------- testing accuracy using hashlib -----------')
    h.update(bytes("Python is the easiest programming language", encoding="ASCII"))
    print("Plaintext: Python is the easiest programming language -----> ", h.hexdigest())


def test_vectors(plaintext, expected_hash):
    print('----------- testing with official vectors -----------')
    result = sha(plaintext)
    print('Plaintext: ', plaintext)
    print('Expected result: ', hex(expected_hash))
    print('Our result: ', result)
    if result == hex(expected_hash):
        print('Success\n')
    else:
        print('Fail\n')


# solve()
main()
unit_test()
test_avalanche("Python is the easiest programming language", "python is the easiest programming language")
test_vectors('abc', 0xA9993E364706816ABA3E25717850C26C9CD0D89D)  # one block
test_vectors('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
             0x84983e441c3bd26ebaae4aa1f95129e5e54670f1)  # two blocks
