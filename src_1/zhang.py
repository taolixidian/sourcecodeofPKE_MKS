# coding=utf-8

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
import time
import random
from functools import reduce

# 生成一个指定长度的随机字符串
def generate_random_str(randomlength=16):
    """
    生成一个指定长度的随机字符串
    """
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz'
    length = len(base_str) - 1
    for i in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return random_str


# 生成关键词集合
def keyword_set(n):
    w=[]
    for i in range(n):
        f = generate_random_str(3)
        if f in w:
            continue
        else:
            w.append(f)
    return w

# 从n个数中取k个数，即实现C_{n}^{k}
def Combinations(L, k):
    """List all combinations: choose k elements from list L"""
    n = len(L)
    result = []
    for i in range(n - k + 1):
        if k > 1:
            newL = L[i + 1:]
            Comb, _ = Combinations(newL, k - 1)
            for item in Comb:
                item.insert(0, L[i])
                result.append(item)
        else:
            result.append([L[i]])
    return result, len(result)

# 将n个数中取出的k个数进行相乘，将所有组合的乘积进行求和
def multi(res):
    sum = 0
    n=len(res[0])
    for i in range(n):
        lis = res[0][i]
        r = reduce(lambda x, y: x * y, lis)  # 对序列lis中元素逐项相乘lambda用法请自行度娘
        sum = sum + r
    return sum

# 求解r(x)的系数ri
def function(w):
    l1=len(w)
    L = []
    for i in range(l1):
        hv = group.hash(w[i])
        L.append(hv)
    n = len(L)
    r_0 = []
    for k in range(n, -1, -1):
        if k == 0:
            res1 = 1
        else:
            res = Combinations(L, k)
            res1 = multi(res)
        r_0.append(res1)
    ri = []
    for i in range(len(r_0)):
        flag = (-1) ** (n - i) * r_0[i]
        ri.append(flag)
    ri[0] = ri[0] + 1

    return [L,ri]

# 密钥生成算法，输入安全参数param，返回[g1, g2, pk, sk]
def KeyGen(param):
    group = PairingGroup(param)
    g1 = group.random(G1)
    g2 = group.random(G2)
    alpha = group.random(ZR)
    sk = g1**alpha
    h = g2**alpha
    pk = [g1, g2, h]
    return [sk, pk]


# 加密算法，输入安全参数param，公钥pk，关键字集合w，返回[c1, c2, ci]
def Enc(pk, w, param):
    group=PairingGroup(param)
    g1, g2, h = pk[0], pk[1], pk[2]
    rho = group.random(ZR)
    c1 = (pair(g1, h)) ** (rho)
    c2 = g2 ** rho
    res = function(w)
    ri = res[1]
    ci = []
    for i in range(len(ri)):
        temp = g2 ** (rho * ri[i])
        ci.append(temp)

    ct=[c1,c2,ci]

    return ct

# 陷门生成算法，输入安全参数param，公钥pk，私钥sk，待搜索关键字集合w，返回[t1, t2, ti]
def Trapdoor(sk,pk, w, param):
    group=PairingGroup(param)
    g1, g2 = pk[0], pk[1]
    r = group.random(ZR)
    beta = group.random(ZR)
    l2 = len(w)
    t1 = g1 ** (r / beta)
    t2 = sk*(g1 ** (r * l2))
    res = function(w)
    L = res[0]
    ri = res[1]
    ti = []
    for i in range(len(ri)):
        temp = 0
        for j in range(l2):
            temp = temp + beta * L[j] ** i
        ti.append(temp)

    td = [t1, t2, ti]
    return td


# 测试算法，输入密文ct，陷门td，返回布尔值True / False
def Test(ct, td):
    c1 = ct[0]
    c2 = ct[1]
    ci = ct[2]
    t1 = td[0]
    t2 = td[1]
    ti = td[2]
    v1 = pair(t2, c2)
    l2 = len(ti)
    s = 1
    for i in range(l2):
        s = s * (ci[i] ** ti[i])
    v2 = c1 * pair(t1, s)

    return v1 == v2

# 关键词猜测攻击，输入密文ct，猜测候选关键词w，返回猜测结果
def KGA(ct, w):
    ci = ct[2]
    v = 0
    if len(w) == 1:
        v = group.hash(w[0])
        if ci[0]/ci[1]== ci[1]**(-v):
            return True
        else:
            return False
    v1 = 0
    v2 = 1
    l = len(w)
    for i in range(len(w)):
        v1 = v1 + group.hash(w[i])
        v2 = v2 * group.hash(w[i])
    if len(w)==2:
        if ci[1] == ci[l] ** (-v1) and ci[0] == ci[l] ** (v2 + 1):
            return True
        else:
            return False
    else:
        if ci[l-1] == ci[l] ** (-v1):
            return "get some information of keywords"
        else:
            return "none"


# 测试代码
if __name__ == "__main__":
    param = 'SS512'
    group = PairingGroup(param)
    w = keyword_set(25)

    s1=time.time()
    [sk, pk] = KeyGen(param)
    time_keygen = time.time()-s1
    print("time_keygen(ms):",round(time_keygen*1000, 3))

    s2 = time.time()
    ct = Enc(pk, w, param)
    time_enc = time.time() - s2
    print("time_enc(ms):",round(time_enc*1000, 3))

    s3 = time.time()
    td = Trapdoor(sk, pk, w, param)
    time_trap = time.time() - s3
    print("time_trap(ms):",round(time_trap*1000, 3))

    s4 = time.time()
    kgares = KGA(ct, w)
    print("KGA RESULT:",kgares)
    time_kga = time.time() - s4
    print("time_kga(μs):", round(time_kga * 1000000, 5))



    s4 = time.time()
    res = Test(ct, td)
    time_test = time.time() - s4
    print("time_test(ms):", round(time_test * 1000, 3))
    print("result of test:", res)
