# coding=utf-8

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
import time
import random
from functools import reduce


# 生成一个指定长度的随机字符串
def generate_random_str(randomlength=16):
    """
    生成一个指定长度的随机字符串
    """
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz,.'
    length = len(base_str) - 1
    for i in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return random_str


# 生成关键词集合
def keyword_set(n):
    w = []
    for i in range(n):
        f = generate_random_str(3)
        if f in w:
            continue
        else:
            w.append(f)
    return w


# 从n个数中选取k个数，即实现C_{n}^{k}
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


# 4.将n个数中取出的k个数进行相乘，将所有组合的乘积进行求和
def multi(res):
    sum = 0
    n = len(res[0])
    for i in range(n):
        lis = res[0][i]
        r = reduce(lambda x, y: x * y, lis)
        sum = sum + r
    return sum


# 求解r(x)的系数ri
def function(w):
    l1 = len(w)
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

    return [L, ri]


# 密钥生成算法，输入安全参数param，返回[g1, g2, pk, sk]
def KeyGen(param):
    group = PairingGroup(param)
    g1 = group.random(G1)
    g2 = group.random(G2)
    alpha = group.random(ZR)
    sk = alpha
    pk = g2 ** alpha
    return [g1, g2, sk, pk]


# 加密算法，输入安全参数param，G1,G2的生成元g1,g2，公钥pk，关键字集合w，返回[c1, c2, c3, ci, hi]
def Enc(g1, g2, pk, w, param):
    group = PairingGroup(param)
    rho = group.random(ZR)
    c1 = (pair(g1, pk)) ** (rho)
    c2 = g2 ** rho
    l1 = len(w)
    ei = [group.random(ZR) for _ in range(l1 + 1)]
    hi = []
    for i in range(l1 + 1):
        h = g2 ** ei[i]
        hi.append(h)
    c3 = 1
    for i in range(l1+1):
        c3 = c3 * (g2 ** ei[i])
    res = function(w)
    ri = res[1]
    ci = []

    for i in range(len(ri)):
        temp = g2 ** (rho * ri[i] + ei[i])
        ci.append(temp)
    ct = [c1, c2, c3, ci, hi]

    return ct


# 陷门生成算法，输入安全参数param，G1,G2的生成元g1,g2，私钥sk，待搜索关键字集合w，返回[t1, t2, ti]
def Trapdoor(g1, sk, w, param):
    group = PairingGroup(param)
    r = group.random(ZR)
    beta = group.random(ZR)
    l2 = len(w)
    t1 = g1 ** (r / beta)
    t2 = g1 ** (sk + r * l2)
    res = function(w)
    L = res[0]
    ri = res[1]
    ti = []
    for i in range(len(ri)):
        temp = 0
        for j in range(l2):
            temp = temp + beta * (L[j] ** i)
        ti.append(temp)
    td = [t1, t2, ti]

    return td


# 测试算法，输入密文ct，陷门td，返回布尔值True / False
def Test(ct, td):
    c1 = ct[0]
    c2 = ct[1]
    c3 = ct[2]
    ci = ct[3]
    hi = ct[4]

    t1 = td[0]
    t2 = td[1]
    ti = td[2]

    v1 = pair(t2, c2)
    l2 = len(ti)
    s = 1
    for i in range(l2):
        s = s * ((ci[i] / hi[i]) ** ti[i])
    v2 = c1 * pair(t1, s)

    return v1 == v2



# 测试代码
if __name__ == "__main__":
    param = 'SS512'
    group = PairingGroup(param)
    w = keyword_set(5)

    s1 = time.time()
    [g1, g2, sk, pk] = KeyGen(param)
    time_keygen = time.time() - s1
    print("time_keygen:",round(time_keygen * 1000, 3))

    s2 = time.time()
    ct = Enc(g1, g2, pk, w, param)
    time_enc = time.time() - s2
    print("time_enc:",round(time_enc * 1000, 3))

    s3 = time.time()
    td = Trapdoor(g1, sk, w, param)
    time_trap = time.time() - s3
    print("time_trap:",round(time_trap * 1000, 3))

    s4 = time.time()
    res = Test(ct, td)
    time_test = time.time() - s4
    print("time_test:", round(time_test * 1000, 3))
    print("result of test:", res)
