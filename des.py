# -*- coding: utf-8 -*-

from typing import List

__all__ = [
    'DES',
    'utils',
]

bt64 = List[int]
bt56 = List[int]
subkey = List[bt56]


class DES:
    '''HUST CAS 系统 des.js 的 Python 实现

    Usage:

        >>> des = DES('1', '2', '3')
        >>> des.encrypt('test')
        'd8d35e5019288c41'
        >>> des.decrypt('d8d35e5019288c41')
        'test'

    对传入的密钥和待加密数据，长度不足时会自动补 0，解密时会忽略

    从 https://pass.hust.edu.cn/cas/comm/js/des.js 改造
    '''

    ENCRYPT = 0
    DECRYPT = 1

    def __init__(self, *keys: str) -> None:
        # region docstring
        '''初始化加/解密所用的 key, 可以指定多个

        对每一个 key 应用一次完整的加/解密过程，key 的长度任意，
        不足 8 byte 时自动以 0 填充，过长的会自动分块

        Args:
            keys (str): 用于加/解密的密钥
        '''
        # endregion
        if not keys:
            raise ValueError('至少应该指定一个 key')

        self.set_key(*keys)

    def encrypt(self, data: str) -> str:
        # region docstring
        '''对传入的数据加密

        不接受非字符串的其他类型数据

        Args:
            data (str): 需要加密的字符串

        Returns:
            str: 加密后的 hex 字符串（小写）
        '''
        # endregion
        bt642bytes = utils.bt642bytes
        result = self._crypt(data, self.ENCRYPT)
        return b''.join(bt642bytes(r) for r in result).hex()

    def decrypt(self, data: str) -> str:
        # region docstring
        '''解密传入的数据

        Args:
            data (str): 待解密字符串

        Raises:
            ValueError: 当传入字符串长度非 16 的倍数时抛出

        Returns:
            str: 解密后的字符串
        '''
        # endregion
        if len(data) % 16 != 0:  # 解密分块大小为 16
            raise ValueError(
                'Invalid data length, data must be a multiple of 16.\n')
        bt642str = utils.bt642str
        result = self._crypt(data, self.DECRYPT)
        return ''.join(bt642str(r) for r in result)

    def _crypt(self, data: str, crypt_type) -> 'list[bt64]':
        # region docstring
        '''加/解密核心

        Args:
            block (bt64): 需要加/解密数据
            crypt_type (int): 运算类型

        Returns:
            list[bt64]: 分块加/解密后的二进制数组
        '''
        # endregion
        init_permute = self._init_permute
        expand_permute = self._expand_permute
        s_box_permute = self._s_box_permute
        p_permute = self._p_permute
        xor = utils.xor
        finally_permute = self._finally_permute

        if crypt_type == self.ENCRYPT:
            data_handler = utils.str2bt64
            block_step = 4
            subkeys = self.ensubkeys
        else:
            data_handler = utils.hex2bt64
            block_step = 16
            subkeys = self.desubkeys

        resule: list[bt64] = []

        for i in range(0, len(data), block_step):
          block = data_handler(data[i:i + block_step])
          ip_byte = block

          for Kns in subkeys:  # 每个 key 对应的块
            for Kn in Kns:  # 每个块生成的 subkey
                ip_byte = init_permute(ip_byte)

                ip_left = ip_byte[:32]
                ip_right = ip_byte[32:]

                for j in range(16):
                    temp_left = ip_left
                    ip_left = ip_right

                    temp_right = xor(expand_permute(ip_right), Kn[j])
                    ip_right = xor(p_permute(s_box_permute(temp_right)), temp_left)

                ip_byte = finally_permute(ip_right + ip_left)
          resule.append(ip_byte)

        return resule

    def set_key(self, *keys: str):
        '''为传入的 key 生成子密钥'''
        self.key_num = len(keys)
        self.ensubkeys: list[list[subkey]] = []
        self.desubkeys: list[list[subkey]] = []
        key2bt64_array = utils.key2bt64_array
        for key in keys:
            ensub_keys: list[subkey] = []
            desub_keys: list[subkey] = []
            key_bit_array = key2bt64_array(key)
            for array in key_bit_array:
                sub_key = self._create_sub_key(array)
                ensub_keys.append(sub_key)
                desub_keys.insert(0, sub_key[::-1])
            self.ensubkeys.append(ensub_keys)
            self.desubkeys.insert(0, desub_keys)

    def _create_sub_key(self, key_bytes: bt64):
        keys: list[bt56] = []
        key = self._permute(key_bytes, self.__pc1)
        L = key[:28]
        R = key[28:]
        for i in range(16):
            for _ in range(self.__left_rotations[i]):
                L.append(L.pop(0))
                R.append(R.pop(0))
            keys.append(self._permute(L+R, self.__pc2))
        return keys

    def _init_permute(self, block: 'list[int]'):
        return self._permute(block, self.__ip)

    def _expand_permute(self, block: 'list[int]'):
        return self._permute(block, self.__expansion_table)

    def _p_permute(self, block: 'list[int]'):
        return self._permute(block, self.__p)

    def _finally_permute(self, block: 'list[int]'):
        return self._permute(block, self.__fp)

    def _permute(self, block: 'list[int]', table: 'list[int]') -> 'list[int]':
        return [block[table[i]] for i in range(len(table))]

    def _s_box_permute(self, block: 'list[int]'):
        result = [0]*32
        sbox = self.__sbox
        i = pos1 = pos2 = 0
        while i < 8:
            m = (block[pos1 + 0] << 1) + block[pos1 + 5]
            n = (block[pos1 + 1] << 3) + \
                (block[pos1 + 2] << 2) + \
                (block[pos1 + 3] << 1) + block[pos1 + 4]

            binary = sbox[i][(m << 4) + n]

            result[pos2 + 0] = (binary & 8) >> 3
            result[pos2 + 1] = (binary & 4) >> 2
            result[pos2 + 2] = (binary & 2) >> 1
            result[pos2 + 3] = binary & 1

            i += 1
            pos1 += 6
            pos2 += 4

        return result
    
    __pc1 = [
        56, 48, 40, 32, 24, 16,  8,
         0, 57, 49, 41, 33, 25, 17,
         9,  1, 58, 50, 42, 34, 26,
        18, 10,  2, 59, 51, 43, 35,
        27, 19, 11,  3, 60, 52, 44,
        36, 28, 20, 12,  4, 61, 53,
        45, 37, 29, 21, 13,  5, 62,
        54, 46, 38, 30, 22, 14,  6
    ]

    __left_rotations = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]

    __pc2 = [
        13, 16, 10, 23,  0,  4,
         2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7,
        15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]

    __ip = [
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8,  0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ]

    __expansion_table = [
        31,  0,  1,  2,  3,  4,
         3,  4,  5,  6,  7,  8,
         7,  8,  9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31,  0
    ]

    __sbox = [
        # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
          0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
          4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

        # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
          3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
          0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

        # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
          1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

        # S4
        [ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
          3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

        # S5
        [ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
          4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

        # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
          9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
          4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

        # S7
        [ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
          1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
          6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

        # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
          1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
          7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
          2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
    __p = [
        15,  6, 19, 20, 28, 11,
        27, 16,  0, 14, 22, 25,
         4, 17, 30,  9,  1,  7,
        23, 13, 31, 26,  2,  8,
        18, 12, 29,  5, 21, 10,
         3, 24
    ]

    __fp = [
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25,
        32,  0, 40,  8, 48, 16, 56, 24
    ]



class utils:
    @staticmethod
    def key2bt64_array(key: str) -> 'list[bt64]':
        '''将给定的 key 分块转换成二进制数组'''
        return list(map(utils.str2bt64, utils.take(4, key)))

    @staticmethod
    def str2bt64(text: str) -> 'list[int]':
        '''将字符串的码位值映射到二进制数组中，每个字符占 16 bit

        返回的二进制数组固定长度 64 bit，输入字符串长度不够补 0，过长则忽略
        '''
        bt64: list[int] = []
        for c in text[:4]:
            k = ord(c)
            bt64.extend((k >> i) & 1 for i in range(15, -1, -1))
        bt64.extend([0]*(64-len(bt64)))
        return bt64

    @staticmethod
    def bt642str(array: 'list[int]') -> str:
        '''将二进制数组转换回字符串

        传入的二进制数组固定长度 64，会移除字符 \0 
        '''
        chr_vals: list[int] = []
        for i in range(0, 64, 16):
            chr_vals.append(sum(array[i + j] << 15 - j for j in range(16)))
        return ''.join(chr(val) for val in chr_vals if val)

    @staticmethod
    def bt642bytes(array: 'list[int]') -> bytes:
        result = []
        for i in range(0, 64, 8):
            bt = (array[i + j] << 7 - j for j in range(8))
            result.append(sum(bt))
        return bytes(result)

    @staticmethod
    def xor(array1: 'list[int]', array2: 'list[int]'):
        return [v1 ^ v2 for v1, v2 in zip(array1, array2)]

    @staticmethod
    def hex2bt64(hex_str: str) -> 'list[int]':
        result: list[int] = []
        for byte in bytes.fromhex(hex_str):
            bt = ((byte >> 7 - i) & 1 for i in range(8))
            result.extend(bt)
        return result

    @staticmethod
    def take(n: int, array):
        for i in range(0, len(array), n):
            yield array[i:i+n]
