import numpy as np
import tkinter as tk
from tkinter import ttk
import time


def xor(in1, in2):
    size = len(in1)
    result = []
    for i in range(size):
        if in1[i] == in2[i]:
            result.append('0')
        else:
            result.append('1')
    return result


# list_to_str:  ''.join(map(str, list))

def hex_to_bin(input_list):  # 十六进制转二进制
    output = []
    for i in input_list:
        output.extend(list(bin(int(i, 16))[2:].zfill(4)))
    return list(output)


def bin_to_hex(input_list):  # 二进制转十六进制
    output = []
    for i in range(int(len(input_list) / 4)):
        output.extend(hex(int(''.join(map(str, input_list[i * 4:i * 4 + 4])), 2))[2:])
    return list(output)


class AES:
    def __init__(self):
        self.p = []
        self.k = []
        self.SBox = np.array([['9', '4', 'A', 'B'], ['D', '1', '8', '5'], ['6', '2', '0', '3'], ['C', 'E', 'F', '7']])
        self.SBox_ = np.array([['A', '5', '9', 'B'], ['1', '7', '8', 'F'], ['6', '0', '2', '3'], ['C', '4', 'D', 'E']])
        self.RCON1 = ['1', '0', '0', '0', '0', '0', '0', '0']
        self.RCON2 = ['0', '0', '1', '1', '0', '0', '0', '0']
        self.row_mix_mat = ['1', '4', '4', '1']
        self.row_mix_mat_ = ['9', '2', '2', '9']
        self.GF = ['0', '0', '0', '1', '0', '0', '1', '1']

    # 行移位
    def row_shift(self, input_mat):
        output = input_mat[0]
        output += input_mat[3]
        output = list(output)
        output.extend(input_mat[2])
        output.extend(input_mat[1])
        return output

    # 半字节代替
    def replace_S(self, input_mat, SBox):
        bin_list = hex_to_bin(input_mat)
        output = []
        for i in range(int(len(bin_list) / 4)):
            small = bin_list[i * 4:i * 4 + 4]
            left = int(''.join(map(str, small[0:2])), 2)
            right = int(''.join(map(str, small[2:4])), 2)
            res = list(bin(int(SBox[left][right], 16))[2:].zfill(4))
            output.extend(res)
        return bin_to_hex(output)

    def cal_g(self, input_w, round_num):  # 密钥扩展的g计算
        temp = bin_to_hex(input_w)
        n = temp[::-1]
        n = self.replace_S(n, self.SBox)
        n = hex_to_bin(n)
        if round_num == 1:
            w_ = xor(n, self.RCON1)
        else:
            w_ = xor(n, self.RCON2)
        return w_

    # 密钥扩展
    def expand_key(self, init_key):
        """第一轮"""
        key1 = list(init_key)
        w0 = init_key[:8]
        w1 = init_key[8:]
        w1_g = self.cal_g(w1, 1)
        w2 = xor(w0, w1_g)
        w3 = xor(w1, w2)
        key2 = w2 + w3  # w2.extend(w3)
        w3_g = self.cal_g(w3, 2)
        w4 = xor(w2, w3_g)
        w5 = xor(w3, w4)
        key3 = w4 + w5  # w4.extend(w5)
        return key1, key2, key3

    # 以下4个函数皆用于列混淆
    def left_shift_no_circle(self, input_list, num):  # 针对GF算数的乘法的移位
        result = ['0' for i in range(8)]
        for i in range(8 - num):
            result[i] = input_list[i + num]
        return result

    def bin_mul(self, a, b):  # GF算数的乘法部分
        m = ['0', '0', '0', '0'] + a
        n = b[::-1]
        result = ['0' for j in range(8)]
        for i in range(4):
            temp = ['0' for j in range(8)]
            if n[i] == '1':
                temp = self.left_shift_no_circle(m, i)
                result = xor(temp, result)
        return result

    def bin_div(self, a, b):  # GF算数的除法部分
        result = a
        while True:
            highest = 7 - result.index('1')
            if highest < 4:
                break
            temp = self.left_shift_no_circle(b, highest - 4)
            result = xor(result, temp)
        return result[4:]

    def cal_GF(self, a, b):
        if a == ['0', '0', '0', '0'] or b == ['0', '0', '0', '0']:  # 有一方是0就不用算了，不然在除法过程会报错
            return ['0', '0', '0', '0']
        result = self.bin_mul(a, b)
        result = self.bin_div(result, self.GF)
        return result

    # 列混淆
    def col_mix(self, input_mat, mix_mat):  # 列混淆
        s00 = hex_to_bin(input_mat[0])
        s01 = hex_to_bin(input_mat[2])
        s10 = hex_to_bin(input_mat[1])
        s11 = hex_to_bin(input_mat[3])
        s00_ = xor(self.cal_GF(hex_to_bin(mix_mat[0]), s00), self.cal_GF(hex_to_bin(mix_mat[1]), s10))
        s01_ = xor(self.cal_GF(hex_to_bin(mix_mat[0]), s01), self.cal_GF(hex_to_bin(mix_mat[1]), s11))
        s10_ = xor(self.cal_GF(hex_to_bin(mix_mat[2]), s00), self.cal_GF(hex_to_bin(mix_mat[3]), s10))
        s11_ = xor(self.cal_GF(hex_to_bin(mix_mat[2]), s01), self.cal_GF(hex_to_bin(mix_mat[3]), s11))
        return bin_to_hex(s00_ + s10_ + s01_ + s11_)

    def encode(self, p, k):
        self.p = list(p)
        self.k = list(k)
        result = self.p
        for i in range(0, len(self.k), 16):
            key1, key2, key3 = self.expand_key(self.k[i:i + 16])
            # 轮密钥加
            mid = xor(key1, result)
            """第1轮"""
            mid = bin_to_hex(mid)  # 转为十六进制
            # 半字节代替
            mid = self.replace_S(mid, self.SBox)
            # 行位移
            mid = self.row_shift(mid)
            # 列混淆
            mid = self.col_mix(mid, self.row_mix_mat)
            mid = hex_to_bin(mid)
            # 轮密钥加
            mid = xor(mid, key2)
            """第2轮"""
            mid = bin_to_hex(mid)
            # 半字节代替
            mid = self.replace_S(mid, self.SBox)
            # 行位移
            mid = self.row_shift(mid)
            mid = hex_to_bin(mid)
            result = xor(mid, key3)
        return ''.join(map(str, result))

    def decode(self, c, k):
        self.k = list(k)
        c = list(c)
        result = c
        for i in range(len(self.k) - 16, -1, -16):
            key1, key2, key3 = self.expand_key(self.k[i:i + 16])
            # 轮密钥加
            mid = xor(key3, result)
            """第1轮"""
            mid = bin_to_hex(mid)  # 转为十六进制
            # 行位移
            mid = self.row_shift(mid)
            # 半字节代替
            mid = self.replace_S(mid, self.SBox_)
            # 轮密钥加
            mid = hex_to_bin(mid)
            mid = xor(mid, key2)
            mid = bin_to_hex(mid)
            # 列混淆
            mid = self.col_mix(mid, self.row_mix_mat_)
            """第2轮"""
            # 行位移
            mid = self.row_shift(mid)
            # 半字节代替
            mid = self.replace_S(mid, self.SBox_)
            mid = hex_to_bin(mid)
            result = xor(mid, key1)
        return ''.join(map(str, result))


class window:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('S-AES双重、三重加密')
        self.plaintext_var = tk.StringVar()  # 明文
        self.key_var = tk.StringVar()  # 密钥
        self.ciphertext_var = tk.StringVar()  # 密文
        self.decrypted_text_var = tk.StringVar()  # 解密后的文本
        self.aes = AES()

    # 加密按钮的动作函数
    def encrypt_action(self):
        plaintext = self.plaintext_var.get()  # 获取明文
        key = self.key_var.get()  # 获取密钥
        ciphertext = self.aes.encode(plaintext, key)  # 使用给定的密钥对明文进行加密
        self.ciphertext_var.set(ciphertext)  # 显示加密后的密文

    def decrypt_action(self):
        ciphertext = self.ciphertext_var.get()  # 获取密文
        key = self.key_var.get()  # 获取密钥
        decrypted_text = self.aes.decode(ciphertext, key)  # 使用给定的密钥对密文进行解密
        self.decrypted_text_var.set(decrypted_text)  # 显示解密后的明文

    def setGUI(self):
        ttk.Label(self.root, text="明文 (16-bit):").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.plaintext_var).grid(row=0, column=1, padx=10, pady=10, ipadx=100, columnspan=3)
        ttk.Label(self.root, text="密钥 (32or48-bit):").grid(row=1, column=0, sticky="w", padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.key_var).grid(row=1, column=1, padx=10, pady=10, ipadx=100, columnspan=3)
        ttk.Button(self.root, text="加密", command=self.encrypt_action).grid(row=2, column=1, padx=(0, 0), pady=10)
        ttk.Button(self.root, text="解密", command=self.decrypt_action).grid(row=2, column=2, padx=(0, 30), pady=10)
        ttk.Label(self.root, text="密文 (16-bit):").grid(row=3, column=0, sticky="w", padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.ciphertext_var).grid(row=3, column=1, padx=10, pady=10, ipadx=100, columnspan=3)
        ttk.Label(self.root, text="解密文本 (16-bit):").grid(row=4, column=0, sticky="w", padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.decrypted_text_var).grid(row=4, column=1, padx=10, pady=10, ipadx=100, columnspan=3)


def get_all_keys(input_ps, input_cs):
    temp = AES()
    list_dict_p = []
    for i in range(65536):
        k1 = bin(i)[2:].zfill(16)
        c1 = temp.encode(input_ps[0], k1)
        dict_p = {'k1': k1, 'c1': c1}
        list_dict_p.append(dict_p)
    keys = []
    key = ''
    for i in range(65536):
        k2 = bin(i)[2:].zfill(16)
        p2 = temp.decode(input_cs[0], k2)
        for j in list_dict_p:
            if j['c1'] == p2:  # 这把key可以破解p1c1明密文对
                key = j['k1'] + k2
                flag = 1
                for n in range(1, len(input_ps), 1):
                    if temp.encode(input_ps[n], key) != input_cs[n]:
                        flag = 0
                        break
                if flag == 1:
                    keys.append(key)
    return keys


class violent_crack:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('S-AES')
        self.plaintext_var = tk.StringVar()  # 明文
        self.plaintext_var2 = tk.StringVar()  # 明文2
        self.key_var = tk.StringVar()  # 密钥
        self.ciphertext_var = tk.StringVar()  # 密文
        self.ciphertext_var2 = tk.StringVar()  # 密文2
        self.cracked_key_var = tk.StringVar()   # 破解后得到的密钥
        self.crack_time = tk.StringVar()    # 破解密钥的时间
        self.aes = AES()

    # 加密按钮的动作函数
    def encrypt_action(self):
        plaintext = self.plaintext_var.get()  # 获取明文
        plaintext2 = self.plaintext_var2.get()
        key = self.key_var.get()  # 获取密钥
        ciphertext = self.aes.encode(plaintext, key)  # 使用给定的密钥对明文进行加密
        ciphertext2 = self.aes.encode(plaintext2, key)
        self.ciphertext_var.set(ciphertext)  # 显示加密后的密文
        self.ciphertext_var2.set(ciphertext2)

    # 中间相遇攻击的动作函数
    def violently_get_key(self):
        plaintext1 = self.plaintext_var.get()
        plaintext2 = self.plaintext_var2.get()
        ciphertext1 = self.ciphertext_var.get()
        ciphertext2 = self.ciphertext_var2.get()
        ps = [plaintext1, plaintext2]
        cs = [ciphertext1, ciphertext2]
        t1 = time.time()
        keys = get_all_keys(ps, cs)
        t2 = time.time()
        key = ''
        for i in range(len(keys)):
            if i == 0:
                key += keys[i]
            else:
                key += ' ' + keys[i]
        self.cracked_key_var.set(key)
        self.crack_time.set(f'Time taken: {t2 - t1:.2f} seconds')

    def setGUI(self):
        ttk.Label(self.root, text="明文1 (16-bit):").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.plaintext_var).grid(row=0, column=1, padx=10, pady=10, ipadx=60, columnspan=2)
        ttk.Label(self.root, text="明文2 (16-bit):").grid(row=1, column=0, sticky="w", padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.plaintext_var2).grid(row=1, column=1, padx=10, pady=10, ipadx=60, columnspan=2)
        ttk.Label(self.root, text="密钥 (32-bit):").grid(row=2, column=0, sticky="w", padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.key_var).grid(row=2, column=1, padx=10, pady=10, ipadx=60, columnspan=2)
        ttk.Button(self.root, text="加密", command=self.encrypt_action).grid(row=3, column=1, padx=(0, 60), pady=10)
        ttk.Button(self.root, text="破解", command=self.violently_get_key).grid(row=3, column=2, padx=0, pady=10)
        ttk.Label(self.root, text="密文1 (16-bit):").grid(row=4, column=0, sticky="w", padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.ciphertext_var).grid(row=4, column=1, padx=10, pady=10, ipadx=60, columnspan=2)
        ttk.Label(self.root, text="密文2 (16-bit):").grid(row=5, column=0, sticky="w", padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.ciphertext_var2).grid(row=5, column=1, padx=10, pady=10, ipadx=60, columnspan=2)
        ttk.Label(self.root, text="解开密钥:").grid(row=6, column=0, sticky="w", padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.cracked_key_var).grid(row=6, column=1, padx=10, pady=10, ipadx=60, columnspan=2)
        ttk.Label(self.root, textvariable=self.crack_time).grid(row=7, column=0, sticky="w", padx=10, pady=10)


if __name__ == '__main__':
    win = window()
    win.setGUI()
    win.root.mainloop()

    win2 = violent_crack()
    win2.setGUI()
    win2.root.mainloop()
