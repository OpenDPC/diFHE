import math
import numpy.random as np_random
import random


def generate_poly():
    """
    随机生成一个多项式用来测试
    :param : None
    :return: 系数大小在0到t-1之间的随机多项式
    """
    poly = []
    for i in range(d):
        poly.append(random.randint(0, t - 1))
    return centered_reduction(poly, t)


def sample(u=3.2):
    """
    模拟高斯分布进行采样，选取噪声时调用
    :param u: 高斯分布的标准差，默认为3.2
    :return: 采样自高斯分布的多项式
    """
    randomNums = np_random.normal(scale=u, size=d)
    p = []
    for pi in randomNums:
        p.append(round(pi))
    return p


def centered_reduction(a, q):
    """
    将系数平移至(-q/2,q/2]
    :param a: 待操作的多项式
    :param q: 多项式对应的模数
    :return: 平移系数后的多项式
    """
    result = []
    for i in range(d):
        result.append(a[i] + q * math.floor(1 / 2 - a[i] / q))
    return result


def poly_add(p1, p2, mod_num):
    """
    对多项式进行加法运算：当mod_num=0时，不进行模运算；否则将多项式的系数模mod_num
    :param p1: 待运算的多项式
    :param p2: 待运算的多项式
    :param mod_num: 模数
    :return: 两个多项式的和
    """
    p = []
    if mod_num != 0:
        for i in range(d):
            p.append((p1[i] + p2[i]) % mod_num)
        return centered_reduction(p, mod_num)
    else:
        for i in range(d):
            p.append((p1[i] + p2[i]))
        return p


def poly_mult(p1, p2, mod_num):
    """
    对多项式进行乘法运算：当mod_num=0时，不进行模运算；否则将多项式的系数模mod_num
    :param p1: 待运算的多项式
    :param p2: 待运算的多项式
    :param mod_num: 模数
    :return: 两个多项式的乘积
    """
    p = []
    for i in range(d):
        p.append(0)
    if mod_num != 0:
        for i in range(d):
            p1_val = p1[i]
            p1_pow = i
            for j in range(d):
                p2_val = p2[j]
                p2_pow = j
                if p1_pow + p2_pow < d:
                    p[p1_pow + p2_pow] = (
                        p[p1_pow + p2_pow] + p1_val * p2_val
                    ) % mod_num
                else:  # 当次数大于d时，次数模d，系数取反
                    p[p1_pow + p2_pow - d] = (
                        p[p1_pow + p2_pow - d] - p1_val * p2_val
                    ) % mod_num
        return centered_reduction(p, mod_num)
    else:
        for i in range(d):
            p1_val = p1[i]
            p1_pow = i
            for j in range(d):
                p2_val = p2[j]
                p2_pow = j
                if p1_pow + p2_pow < d:
                    p[p1_pow + p2_pow] = p[p1_pow + p2_pow] + p1_val * p2_val
                else:  # 当次数大于d时，次数模d，系数取反
                    p[p1_pow + p2_pow - d] = p[p1_pow + p2_pow - d] - p1_val * p2_val
        return p


def poly_mult_const(p1, const_num, mod_num):
    """
    多项式与常量相乘
    :param p1: 待运算的多项式
    :param const_num: 参与运算的常数
    :param mod_num: 模数
    :return: 多项式与常数的乘积
    """
    p = []
    for i in range(d):
        p.append(p1[i] * const_num % mod_num)
    return centered_reduction(p, mod_num)


def secret_key_gen():
    """
    生成私钥
    s ← R_2
    :param : None
    :return: 私钥
    """
    s = []
    for i in range(d):
        s.append(int(np_random.randint(2)))
    return s


def public_key_gen(sk):
    """
    生成公钥
    a ← R_q
    e ← χ
    pk = ([-(as+e)]_q,a)
    :param sk: 私钥
    :return: 公钥
    """
    a = []
    for i in range(d):
        a.append(int(np_random.randint(-(q - 1) // 2, q // 2)))
    e = sample()

    tmp = poly_add(poly_mult(a, sk, q), e, q)
    p0 = []
    for tmpi in tmp:
        p0.append(-tmpi)
    p1 = centered_reduction(a, q)
    pk = (p0, p1)
    return pk


def encrypt(pk, m_poly):
    """
    加密
    u ← R_2
    e1 ← χ
    e2 ← χ
    generate ct = (c0, c1)
    :param pk: 公钥
    :param m_poly: 明文多项式
    :return: 密文
    """
    p0 = pk[0]
    p1 = pk[1]
    # u = sample()
    u = []
    for i in range(d):
        u.append(int(np_random.randint(2)))
    e1 = sample()
    e2 = sample()

    # e1 = [0 for _ in range(d)]
    # e2 = [0 for _ in range(d)]
    c0 = poly_add(
        poly_add(poly_mult(p0, u, q), e1, q),
        poly_mult_const(m_poly, math.floor(q / t), q),
        q,
    )
    c1 = poly_add(poly_mult(p1, u, q), e2, q)
    ct = (c0, c1)
    return ct


def decrypt(sk, ct):
    """
    解密 = 去掉掩码项 + 除以缩放因子 + 四舍五入
    :param sk: 私钥
    :param ct: 密文
    :return: 明文多项式
    """
    c0 = ct[0]
    c1 = ct[1]
    tmp = poly_add(c0, poly_mult(c1, sk, q), q)
    p = []
    for tmpi in tmp:
        p.append(round(tmpi * t / q) % t)
    return centered_reduction(p, t)


def add_ct(ct1, ct2):
    """
    同态加法
    :param ct1: 待运算的密文
    :param ct2: 待运算的密文
    :return: 进行同态加法后的新密文
    """
    ct = []
    ct.append(poly_add(ct1[0], ct2[0], q))
    ct.append(poly_add(ct1[1], ct2[1], q))
    return ct


def mult_ct(ct1, ct2):
    """
    同态乘法（生成c0,c1,c2三个密文）
    :param ct1: 待运算的密文
    :param ct2: 待运算的密文
    :return: 进行同态乘法后的新密文
    """
    c0 = poly_mult(ct1[0], ct2[0], 0)
    c1 = poly_add(poly_mult(ct1[1], ct2[0], 0), poly_mult(ct1[0], ct2[1], 0), 0)
    c2 = poly_mult(ct1[1], ct2[1], 0)
    for i in range(d):
        c0[i] = round(c0[i] * t / q) % q
        c1[i] = round(c1[i] * t / q) % q
        c2[i] = round(c2[i] * t / q) % q
    return [c0, c1, c2]


def decrypt_HE_mult(sk, ct):
    """
    不使用重线性化技术，直接对生成的三个密文进行解密
    :param sk: 私钥
    :param ct: 同态运算后未进行重线性化的密文
    :return: 明文多项式
    """
    tmp = poly_add(
        poly_add(ct[0], poly_mult(ct[1], sk, q), q),
        poly_mult(ct[2], poly_mult(sk, sk, q), q),
        q,
    )
    p = []
    for tmpi in tmp:
        p.append(round(tmpi * t / q) % t)
    return centered_reduction(p, t)


def main():
    sk = secret_key_gen()
    pk = public_key_gen(sk)

    print("##加解密验证##\n")
    m_poly = generate_poly()
    print("明文：  ", m_poly)
    ciphertext = encrypt(pk, m_poly)
    print("密文：  ", ciphertext)
    plaintext_poly = decrypt(sk, ciphertext)
    print("解密得：", plaintext_poly)

    # 加法同态
    print("\n##同态加法验证##\n")
    m_poly1 = generate_poly()
    ct1 = encrypt(pk, m_poly1)
    m_poly2 = generate_poly()
    ct2 = encrypt(pk, m_poly2)
    print("明文和：", poly_add(m_poly1, m_poly2, t))
    plaintext_poly = decrypt(sk, add_ct(ct1, ct2))
    print("解密得：", plaintext_poly)

    # 乘法同态
    print("\n##同态乘法验证##\n")
    m_poly3 = generate_poly()
    ct3 = encrypt(pk, m_poly3)
    m_poly4 = generate_poly()
    ct4 = encrypt(pk, m_poly4)
    print("明文乘积：  ", poly_mult(m_poly3, m_poly4, t))
    ct_mult = mult_ct(ct3, ct4)
    plaintext_poly = decrypt_HE_mult(sk, ct_mult)
    print("乘法解密：  ", plaintext_poly)


if __name__ == "__main__":
    ####################################参数选取####################################
    d = 32  # 多项式的最大次数，为2的幂次。需要确保同态计算过程中明文多项式的次数小于d
    t = 16  # 明文模量
    q = 132120577  # 密文模量,必须远大于明文模量

    T = 256
    l = math.floor(math.log(q, T))

    p = pow(q, 3) + 1
    ################################################################################
    main()
