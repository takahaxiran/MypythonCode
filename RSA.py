from random import randint
class RSA_key():
    def __init__(self,share_key=1,public_key=1,private_key=1):
        self.share_key = share_key
        self.public_key = public_key
        self.private_key = private_key

    def produce_key(self):
        p = Create_Sushu()
        q = p
        while p == q:
            q = Create_Sushu()
        n = p * q
        oula = Oula(p, q)
        self.public_key = Creat_E(oula)
        self.private_key = Compute_D(oula,self.public_key)
        self.share_key = n
        return self

"""判断是否是素数"""
def is_sushu(sushu):
    for i in range(2, sushu):
        if sushu % i == 0:
            return False
    return True

"""随机生成指定范围的大素数"""
def Create_Sushu():
    while True:
        sushu = randint(100, 1000)  # 下限越大，加密越安全，此处考虑计算时间，取值较小
        if is_sushu(sushu):
            return sushu

"""计算欧拉函数"""

def Oula(sushu1,sushu2):
    return (sushu1 - 1) * (sushu2 - 1)


"""判断是否互质"""
def Is_Huzhi(int_min,int_max):
    for i in range(2,int_min+1):
        if int_min % i == 0 and int_max % i == 0:
            return False
        return True


"""计算公钥，直接计算编程较简单，此处考虑了计算效率的优化"""
def Creat_E(oula):
    top = oula
    while True:
        i = randint(2, top)
        for e in range(i, top):
            if Is_Huzhi(e, oula):
                return e
        top = i

"""计算私钥"""
def Compute_D(oula,e):
    k = 1
    while ( k*oula+1 )% e != 0:
        k+=1
    return int((k*oula+1)/e)


"""
将字符串转成list
"""
def Transfer_To_list(messages):
    result = []
    for message in messages:
        if message == ' ':
            result.append()
"""
将字符串转成ASCII
"""
def Transfer_To_Ascii(messages):
    result = []
    for message in messages:
        result.append(  ord(message) )
    return result

"""
将列表转化成字符串
"""
def Transfer_To_String(string_list):
    string = ''.join(string_list)
    return string

def RSAecrypt(m,seed_key):

    m_list = Transfer_To_Ascii(m)

    print("正在加密...")
    # print(seed_key.share_key)
    c_list = []
    for m in m_list:
        c = m ** seed_key.public_key % seed_key.share_key
        c_list.append(c)
    print(f"密文：{c_list}")
    return c_list

def atoi(s):
    return int("".join([str(x) for x in s]))

def RSAdecrypt(c_list,seed_key):
    print("正在解密...")
    decode_messages = []
    try:
        seed_key.share_key = atoi(seed_key.share_key)
        seed_key.public_key = atoi(seed_key.public_key)
        seed_key.private_key = atoi(seed_key.private_key)
    except:
        print("lose")
    for c in c_list:
        decode_message = c ** seed_key.private_key % seed_key.share_key
        decode_messages.append(chr(decode_message))
    print(f"解密信息：{Transfer_To_String(decode_messages)}")
    return Transfer_To_String(decode_messages)

"""生成密钥"""
_key = RSA_key()
_key = _key.produce_key()
def test():
    m = input('待加密信息：')
    global _key
    c_list = RSAecrypt(m, _key)
    RSAdecrypt(c_list, _key)

if __name__ == "__main__":
    test()
    """
    p、q为大素数
    n=p*q
    oula = （p-1）* （q-1）
    e 为公钥
    d 为私钥
    """

    """print("通信开始，正在计算公钥与私钥...")
    time_start = datetime.now()
    p = Create_Sushu()
    q = p
    while p ==q :
        q = Create_Sushu()
    n = p * q
    oula = Oula(p, q)
    e = Creat_E(oula)
    d = Compute_D(oula,e)
    time_end = datetime.now()
    print(f"计算完成，用时{str(time_end -time_start)}秒 ")
    print(f"公钥：n = {str(n)} , e = {str(e)}")
    print(f"私钥：n = {str(n)} , d = {str(d)}")
    #print('p='+str(p)+'\n'+'q='+str(q)+'\n'+'n='+str(n)+'\n'+'oula='+str(oula)+'\n'+'d='+str(d)+'\n')

    m = input('待加密信息：')
    m_list = Transfer_To_Ascii(m)

    print("正在加密...")
    c_list = []
    for m in m_list:
        c = m**e%n
        c_list.append(c)
    print(f"密文：{c_list}")

    print("正在解密...")
    decode_messages=[]
    for c in c_list:
        decode_message = c**d%n
        decode_messages.append(chr(decode_message))
    print(f"解密信息：{Transfer_To_String(decode_messages)}")
    """