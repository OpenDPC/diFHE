import math
from numpy import *


def Powersof2(b):
    """
    将向量的每个元素分别与2的幂次相乘
    :param b: 待处理的向量
    :return: 处理后的向量
    """
    result = []
    for bi in b:
        for j in range(l):
            result.append(pow(2, j) * bi)
    return array(result)


def BitDecomp(A):
    """
    二进制分解
    :param A: 待分解的矩阵（或向量）
    :return: 分解后的矩阵（或向量）
    """
    result_mat = []
    for a in A:
        result = []
        for ai in a:
            for j in range(l):
                if ai != 0:
                    result.append(ai % 2)
                    ai //= 2
                else:
                    result.append(0)
        result_mat.append(result)
    return array(result_mat)


def BitDecomp_inverse(A):
    """
    二进制重组
    :param 待重组的矩阵（或向量）
    :return: 重组后的矩阵（或向量）
    """
    result_mat = []
    for a in A:
        result = []
        for i in range(len(a) // l):
            ri = 0
            for j in range(l):
                ri += pow(2, j) * a[i * l + j]
            result.append(ri)
        result_mat.append(result)
    return array(result_mat)


def Flatten(c):
    """
    将矩阵重组后分解，目的是得到一个元素只包含01的矩阵
    :param c: 待处理的矩阵
    :return: 处理后的矩阵
    """
    tmp = BitDecomp_inverse(c)
    return BitDecomp(tmp)


def Setup():
    """
    参数选取
    :param : None
    :return: 参数，包含模数q以及行列数m、n
    """
    global l, N
    q = pow(2, 11)
    n = pow(2, 4)
    l = math.floor(math.log2(q)) + 1
    m = 2 * n * l
    N = (n + 1) * l
    params = {"q": q, "n": n, "m": m}
    return params


def SecretKeyGen(params):
    """
    生成私钥
    :param params: 方案相关参数
    :return: 私钥
    """
    t = random.randint(0, params["q"], params["n"])
    s = [1]
    for ti in t:
        s.append(-ti)
    return array(s)


def PublicKeyGen(params, sk):
    """
    生成公钥
    :param params: 方案参数
    :param sk: 私钥
    :return: 公钥
    """
    B = []
    for i in range(params["m"]):
        Bi = []
        for j in range(params["n"]):
            Bi.append(random.randint(0, params["q"]))
        B.append(Bi)
    B = array(B)

    randomNums = random.normal(scale=params["q"] // (8 * params["m"]), size=params["m"])
    e = []
    for err in randomNums:
        e.append(round(err))
    e = array(e)

    t = delete(sk, 0)
    for i in range(len(t)):
        t[i] = -t[i]
    b = (dot(B, t) + e) % params["q"]

    # 得到拼接矩阵A=(b，B)，且 A·s = e
    A = hstack((b.reshape(b.shape[0], 1), B))
    return A


def Enc(params, pk, u):
    """
    加密
    :param params: 方案参数
    :param pk: 公钥
    :param u: 明文
    :return: 密文
    """
    R = []
    for i in range(N):
        Ri = []
        for j in range(params["m"]):
            Ri.append(random.randint(0, 2))
        R.append(Ri)
    R = array(R)
    I = eye(N)
    A = pk
    C = Flatten(I * u + BitDecomp(dot(R, A)) % params["q"])
    return C


def MPDec(params, sk, C):
    """
    解密（明文空间为Z_q）
    :param params: 方案参数
    :param sk: 私钥
    :param C: 密文
    :return: 明文
    """
    u = 0
    v = Powersof2(sk)
    Cv = (dot(C, v) % params["q"])[: l - 1]
    g = v[: l - 1]
    bound = params["q"] // 4
    for i in range(l - 2, -1, -1):
        u = u + pow(2, l - 2 - i) * (
            (Cv[i] - pow(2, i) * u) >= bound or (Cv[i] - pow(2, i) * u) < -bound
        )
    return u


def MultConst(C, alpha, params):
    """
    与常数同态相乘
    :param C: 密文
    :param alpha: 一个常数
    :param params: 方案参数
    :return: 新密文
    """
    M = eye(N) * alpha
    return Flatten(dot(M, C) % params["q"])


def Add(C1, C2, params):
    """
    同态加法
    :param C1: 待运算的密文
    :param C2: 待运算的密文
    :return: 新密文
    """
    return Flatten((C1 + C2) % params["q"])


def Mult(C1, C2, params):
    """
    同态乘法
    :param C1: 待运算的密文
    :param C2: 待运算的密文
    :return: 新密文
    """
    return Flatten(dot(C1, C2) % params["q"])


def main():
    params = Setup()
    sk = SecretKeyGen(params)
    pk = PublicKeyGen(params, sk)
    u = 31
    C = Enc(params, pk, u)
    P = MPDec(params, sk, C)
    print("Calculating...")
    print("加解密验证：")
    print("message = ", u)
    print("Plaintext = Dec(C) =", P, "\n")

    alpha = 20
    u0 = 31
    C0 = Enc(params, pk, u0)
    u1 = alpha * u0
    C1 = MultConst(C0, alpha, params)
    P_mult_const = MPDec(params, sk, C1)
    print("数乘同态验证：")
    print("message = u*alpha = ", u0, "*", alpha, " = ", u1)
    print("Plaintext = Dec(alpha*C) =", P_mult_const, "\n")

    u2 = 32
    u3 = 45
    C2 = Enc(params, pk, u2)
    C3 = Enc(params, pk, u3)
    P_add = MPDec(params, sk, Add(C2, C3, params))
    print("加法同态验证：")
    print("message = u2+u3 = ", u2, "+", u3, " = ", u2 + u3)
    print("Plaintext = Dec(C2+C3) =", P_add, "\n")

    P_mult = MPDec(params, sk, Mult(C2, C3, params))
    print("乘法同态验证：")
    print("message = u2*u3 = ", u2, "*", u3, " = ", u2 * u3)
    print("Plaintext = Dec(C2*C3) =", P_mult, "\n")


if __name__ == "__main__":
    l = 0
    N = 0
    main()
