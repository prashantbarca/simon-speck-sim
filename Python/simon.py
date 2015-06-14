from __future__ import print_function
from collections import deque

__author__ = 'inmcm'


class SimonCipher:

    z0 = 0b11111010001001010110000111001101111101000100101011000011100110
    z1 = 0b10001110111110010011000010110101000111011111001001100001011010
    z2 = 0b10101111011100000011010010011000101000010001111110010110110011
    z3 = 0b11011011101011000110010111100000010010001010011100110100001111
    z4 = 0b11010001111001101011011000100000010111000011001010010011101111

    # valid cipher configurations stored:
    # block_size:{key_size:(number_rounds,z sequence)}
    __valid_setups = {32: {64: (32, z0)},
                      48: {72: (36, z0), 96: (36, z1)},
                      64: {96: (42, z2), 128: (44, z3)},
                      96: {96: (52, z2), 144: (54, z3)},
                      128: {128: (68, z2), 192: (69, z3), 256: (72, z4)}}

    __valid_modes = ['ECB', 'CTR', 'CBC', 'PCBC', 'CFB', 'OFB']

    def __init__(self, key, key_size=128, block_size=128, mode='ECB', init=0, counter=0):
        """
        Initialize an instance of the Simon block cipher.
        :param key: Int representation of the encryption key
        :param key_size: Int representing the encryption key in bits
        :param block_size: Int representing the block size in bits
        :param mode: String representing which cipher block mode the object should initialize with
        :param init: IV for CTR, CBC, PCBC, CFB, and OFB modes
        :param counter: Initial Conunter value for CTR mode
        :return: None
        """

        # Setup block/word size
        try:
            self.possible_setups = self.__valid_setups[block_size]
            self.word_size = block_size >> 1
        except KeyError:
            print('Invalid block size!')
            print('Please use one of the following block sizes:', [x for x in self.__valid_setups.keys()])
            raise

        # Setup Number of Rounds, Z Sequence, and Key Size
        try:
            self.rounds, self.zseq = self.possible_setups[key_size]
            self.key_size = key_size
        except KeyError:
            print('Invalid key size for selected block size!!')
            print('Please use one of the following key sizes:', [x for x in self.possible_setups.keys()])
            raise

        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = (2 ** self.word_size) - 1

        # Parse the given iv and truncate it to the block length
        try:
            self.iv = init & ((2 ** block_size) - 1)
        except (ValueError, TypeError):
            print('Invalid IV Value!')
            print('Please Provide IV as int')
            raise

        # Parse the given Counter and truncate it to the block length
        try:
            self.counter = counter & ((2 ** block_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Counter Value!')
            print('Please Provide Counter as int')
            raise

        # Check Cipher Mode
        try:
            position = self.__valid_modes.index(mode)
            self.mode = self.__valid_modes[position]
        except ValueError:
            print('Invalid cipher mode!')
            print('Please use one of the following block cipher modes:', self.__valid_modes)
            raise

        # Parse the given key and truncate it to the key length
        try:
            self.key = key & ((2 ** self.key_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Key Value!')
            print('Please Provide Key as int')
            raise

        # Pre-compile key schedule
        m = self.key_size // self.word_size
        self.key_schedule = []

        # Create list of subwords from encryption key
        k_init = [((self.key >> (self.word_size * ((m-1) - x))) & self.mod_mask) for x in range(m)]

        k_reg = deque(k_init)  # Use queue to manage key subwords

        round_constant = self.mod_mask ^ 3  # Round Constant is 0xFFFF..FC

        # Generate all round keys
        for x in range(self.rounds):

            rs_3 = ((k_reg[0] << (self.word_size - 3)) + (k_reg[0] >> 3)) & self.mod_mask

            if m == 4:
                rs_3 = rs_3 ^ k_reg[2]

            rs_1 = ((rs_3 << (self.word_size - 1)) + (rs_3 >> 1)) & self.mod_mask

            c_z = (self.zseq >> (61 - (x % 62)) & 1) ^ round_constant

            new_k = c_z ^ rs_1 ^ rs_3 ^ k_reg[m - 1]

            self.key_schedule.append(k_reg.pop())
            k_reg.appendleft(new_k)

    def round_function(self, x, y, k):
        """
        Complete One Feistel Round
        :param x: Upper bits of current plaintext
        :param y: Lower bits of current plaintext
        :param k: Round Key
        :return: Upper and Lower ciphertext segments
        """

        # Generate all circular shifts
        ls_1_x = ((x >> (self.word_size - 1)) + (x << 1)) & self.mod_mask
        ls_8_x = ((x >> (self.word_size - 8)) + (x << 8)) & self.mod_mask
        ls_2_x = ((x >> (self.word_size - 2)) + (x << 2)) & self.mod_mask

        # XOR Chain
        xor_1 = (ls_1_x & ls_8_x) ^ y
        xor_2 = xor_1 ^ ls_2_x
        new_x = k ^ xor_2

        return new_x, x

    def round_function_inv(self, x, y, k):
        """Complete One Inverse Feistel Round
        :param x: Upper bits of current ciphertext
        :param y: Lower bits of current ciphertext
        :param k: Round Key
        :return: Upper and Lower plaintext segments
        """

        # Generate all circular shifts
        ls_1_y = ((y >> (self.word_size - 1)) + (y << 1)) & self.mod_mask
        ls_8_y = ((y >> (self.word_size - 8)) + (y << 8)) & self.mod_mask
        ls_2_y = ((y >> (self.word_size - 2)) + (y << 2)) & self.mod_mask

        # Inverse XOR Chain
        xor_1 = k ^ x
        xor_2 = xor_1 ^ ls_2_y
        new_x = (ls_1_y & ls_8_y) ^ xor_2

        return y, new_x

    def encrypt(self, plaintext):
        """
        Process new plaintext into ciphertext based on current cipher object setup
        :param plaintext: Int representing value to encrypt
        :return: Int representing encrypted value
        """
        try:
            b = plaintext >> self.word_size
            a = plaintext & self.mod_mask
        except TypeError:
            print('Invalid plaintext!')
            print('Please provide plaintext at int')
            raise

        if self.mode == 'ECB':
            for x in range(self.rounds):
                b, a = self.round_function(b, a, self.key_schedule[x])

        elif self.mode == 'CTR':
            d = self.iv & self.mod_mask
            c = self.counter & self.mod_mask
            for x in range(self.rounds):
                d, c = self.round_function(d, c, self.key_schedule[x])
            b ^= d
            a ^= c
            self.counter += 1

        elif self.mode == 'CBC':
            d = self.iv >> self.word_size
            c = self.iv & self.mod_mask
            b ^= d
            a ^= c
            for x in range(self.rounds):
                b, a = self.round_function(b, a, self.key_schedule[x])

            self.iv = (b << self.word_size) + a

        elif self.mode == 'PCBC':
            d = self.iv >> self.word_size
            c = self.iv & self.mod_mask
            f, e = b, a
            b ^= d
            a ^= c
            for x in range(self.rounds):
                b, a = self.round_function(b, a, self.key_schedule[x])

            self.iv = ((b ^ f) << self.word_size) + (a ^ e)

        elif self.mode == 'CFB':
            d = self.iv >> self.word_size
            c = self.iv & self.mod_mask
            for x in range(self.rounds):
                d, c = self.round_function(d, c, self.key_schedule[x])
            b ^= d
            a ^= c
            self.iv = (b << self.word_size) + a

        elif self.mode == 'OFB':
            d = self.iv >> self.word_size
            c = self.iv & self.mod_mask
            for x in range(self.rounds):
                d, c = self.round_function(d, c, self.key_schedule[x])

            self.iv = (d << self.word_size) + c

            b ^= d
            a ^= c

        ciphertext = (b << self.word_size) + a

        return ciphertext

    def decrypt(self, ciphertext):
        """
        Process new ciphertest into plaintext based on current cipher object setup
        :param ciphertext: Int representing value to encrypt
        :return: Int representing decrypted value
        """
        try:
            b = ciphertext >> self.word_size
            a = ciphertext & self.mod_mask
        except TypeError:
            print('Invalid plaintext!')
            print('Please provide plaintext at int')
            raise

        if self.mode == 'ECB':
            for x in range(self.rounds):
                b, a = self.round_function_inv(b, a, self.key_schedule[self.rounds - (x + 1)])

        elif self.mode == 'CTR':
            pass

        elif self.mode == 'CBC':
            pass

        elif self.mode == 'PCBC':
            pass

        elif self.mode == 'CFB':
            pass

        elif self.mode == 'OFB':
            pass

        plaintext = (b << self.word_size) + a

        return plaintext


if __name__ == "__main__":
    w = SimonCipher(0x1918111009080100, key_size=64, block_size=32)
    t = w.encrypt(0x65656877)
    print(hex(t))
