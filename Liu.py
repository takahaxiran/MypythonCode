# import numpy as np
# import random
# e = 0.2
# temp = []
# begin = -0.8
# pos_sum = int(0.8/e)
# for i in  range(0,2*pos_sum+1):
#     end = begin+i*e
#     end = round(end,1)
#     temp.append(end)
# temp1 = temp + temp
# temp1.sort()
# temp_np = np.array(temp1)
# # print(temp1)
# # print(pos_sum)
# print(temp1[:2*pos_sum])
# print(temp1[2*pos_sum+2:])
# # print(temp_np)
# pos = random.randint(1,3)
# print(pos)
# print(pos)

# print("hello world")

#@ author: small-cai
#@ data :2021-12-24 eve
#! RC4
#! 流密码将明文消息按字符逐位加密，它采用密钥流生成器（KG），
#! 从种子密钥生成一串密钥流字符来加密信息，每个明文字母被密钥流中不同的密钥字符加密。

#? a是n个寄存器（状态）
#? 是种子密钥，对应着a的系数

#? 输出是a1&cn
#? 迭代方程为：
#? ai(t+1）=ai+1（t）（i=1,2,…,n-1)
#? an(t+1)=Σ(ci*an-i(t)) 

import base64
import hashlib
import os
from io import BytesIO

def get_str_bits(s:str):
    list_b = []
    for i in s:
        list_b.append((ord(i) - ord('0'))) #转字符串为对印的给ASCII码
    return list_b

class LFSR():
    def __init__(self, c=None, a=None, lenc=0): #c是开关（系数），a是初始状态 
        if a is None:
            a = []
        if c is None:
            c = []
        self.a = a
        self.c = c
        self.lenc = lenc
        lena = len(a)
        #如果lena比lenc短，那么将其拓展 
        

    def LeftShift(self):
        lastb = 0
        lenc = self.lenc
        for i in range(lenc):
            lastb = lastb ^ (self.a[i] & self.c[i])
        b = self.a[1:]
        b.append(lastb)
        outp = self.a[0]   
        #体现linear  
        self.a = b
        return outp

class cypto_LFSR():
    def __init__(self, key, lfsr1 = None, lfsr2 = None):
        if lfsr1 is None:
            lfsr1 = [0, 1, 0, 1]
        if lfsr2 is None:
            lfsr2 = [0, 0, 1, 1]
        Keymap = key
        lenk = len(Keymap)
        self.lfsr1 = LFSR(Keymap, lfsr1, lenk)
        self.lfsr2 = LFSR(Keymap, lfsr2, lenk)  #生成LFSR伪随机序列 
        self.Key = Keymap
        self.lc = 0

    def GetBit(self):
        ak = self.lfsr1.LeftShift()
        bk = self.lfsr2.LeftShift()
        ck = ak ^ (~(ak ^ bk) & self.lc)  # JK触发器  ck = ak ^ (~(ak ^ bk) & ck-1)
        self.lc = ck
        return int(ck)

    def do_crypt(self, LFSR_msg):
        text = []
        for i in LFSR_msg:
            j, cnt = i, 8
            tmp = []
            while cnt > 0:
                tmp.append(self.GetBit() ^ (j & 1))#低位放在了前面 
                j = j >> 1
                cnt = cnt - 1
            res = 0
            for iti in range(7, -1, - 1):#按照[7，6，5，4，3，2，1]的顺序 
                res = res << 1
                res = res + tmp[iti]
            text.append(res)
        return bytes(text)

class RC4(object):
    def __init__(self, key=None):
        self.key = hashlib.md5(key.encode("utf-8")).hexdigest()

    def encode(self, in_stream, out_stream):
        sbox = self.sbox()
        while 1:
            chunk = in_stream.read(8)

            if not chunk:
                break

            out_chuck = bytearray()
            for bt in chunk:
                out_chuck.append(bt ^ next(sbox))
            out_stream.write(bytes(out_chuck))

    def sbox(self):
        keylength = len(self.key)

        s = list(range(256))  # init S box

        j = 0
        for i in range(255):
            j = (j + s[i] + ord(self.key[i % keylength])) % 256
            s[i], s[j] = s[j], s[i]

        i = 0
        j = 0
        while 1:
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            yield s[(s[i] + s[j]) % 256]


def encrypt(in_stream: BytesIO, out_stream: BytesIO, pwd: str):
    rc4_cryptor = RC4(pwd)
    rc4_cryptor.encode(in_stream, out_stream)

#! 加密
def encrypt_str(data: str, pwd: str):
    in_stream = BytesIO()
    out_stream = BytesIO()

    data_bytes = data.encode("utf-8")

    # 魔改 引入随机IV打乱原文，不喜欢的话就删之吧。：）
    iv = os.urandom(1)[0]
    tp_v = iv

    data_xor_iv = bytearray()
    for bt in data_bytes:
        data_xor_iv.append(bt ^ tp_v)
        tp_v = bt ^ tp_v

    in_stream.write(data_xor_iv)
    in_stream.seek(0)

    encrypt(in_stream, out_stream, pwd)

    enc_bytes = bytes([iv]) + out_stream.getvalue()
    b64_str = base64.urlsafe_b64encode(enc_bytes)
    return b64_str.decode("utf-8")

#? 解密 RC4
def decrypt_str(data: str, pwd: str):
    data_bytes = base64.urlsafe_b64decode(data)
    in_stream = BytesIO()
    out_stream = BytesIO()

    iv = data_bytes[:1][0]

    in_stream.write(data_bytes[1:])
    in_stream.seek(0)

    encrypt(in_stream, out_stream, pwd)
    dec_bytes = out_stream.getvalue()

    data_xor_iv = bytearray()
    for bt in dec_bytes:
        data_xor_iv.append(bt ^ iv)
        iv = bt

    return data_xor_iv.decode('utf-8')

#? 解密LFSR


if __name__ == "__main__":
    operater = input("请问你要选择 RSA or LFSR: ")
    print("\n")
    if operater == "RSA":
        test_byte_data = input("请输入要加密的明文：")
        seed_key = input("请输入一个种子密钥：")
        ret = encrypt_str(test_byte_data, seed_key)
        print("生成的密文为{},密文长度为{}".format(ret,len(ret)))
        # input()
        ret_temp = input("请输入你想要解密的密文")
        seed_key_temp = seed_key 
        ret = decrypt_str(ret, seed_key_temp)
        print("解密为{}".format(ret))
        assert test_byte_data == ret #用于判断
    elif operater=="LFSR":
        test_byte_data = input("请输入要加密的明文：")
        k = input("请输入连续的01序列如：1001")
        key = get_str_bits(k)
        l = cypto_LFSR(key)
        l_temp = l.do_crypt(get_str_bits(test_byte_data))
         
        print(l_temp)
        
       
    



