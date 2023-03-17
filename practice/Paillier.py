import gmpy2
import libnum


def L(x, n):
    """
    方案中定义的函数: L(x) = (x - 1) / n
    :param x
    :param n
    :return: L(x)
    """
    return (x - 1) // n


def key_generation():
    """
    生成加解密所需的公钥和私钥
    :param : None
    :return: 公私钥
    """
    p = libnum.generate_prime(1024)
    q = libnum.generate_prime(1024)

    n = p * q
    lmd = (p - 1) * (q - 1)
    for g in range(1, n ** 2):
        if (
            gmpy2.gcd(n ** 2, g) == 1
            and gmpy2.gcd(L(gmpy2.powmod(g, lmd, n ** 2), n), n) == 1  # 为了保证解密的时候其逆元存在
        ):
            break
    public_key = (n, g)
    private_key = lmd
    return public_key, private_key


def encrypt(m, public_key):
    """
    加密
    c = g^m * r^n (mod n^2)
    :param m: 明文
    :param public_key: 公钥
    :return: 密文
    """
    n, g = public_key
    for r in range(1, n ** 2):
        if gmpy2.gcd(n ** 2, r) == 1:
            break
    c = gmpy2.powmod(g, m, n ** 2) * gmpy2.powmod(r, n, n ** 2) % n ** 2
    return c


def decrypt(c, private_key, public_key):
    """
    解密
    :param c: 密文
    :param private_key: 私钥
    :param public_key: 公钥
    :return: 明文
    """
    lmd = private_key
    n, g = public_key
    m = (
        L(gmpy2.powmod(c, lmd, n ** 2), n)
        * gmpy2.invert(L(gmpy2.powmod(g, lmd, n ** 2), n), n)
        % n
    )
    return m


def main():
    print("加解密验证")
    public_key, private_key = key_generation()
    m = "hello"
    print("message:" + m)
    c = encrypt(libnum.s2n(m), public_key)
    print("ciphertext:" + str(c))
    result = libnum.n2s(int(decrypt(c, private_key, public_key))).decode("utf-8")
    print("plaintext:" + result)

    print("###################################################")
    print("加法同态验证")
    m1 = 15
    print("message1:" + str(m1))
    m2 = 24
    print("message2:" + str(m2))
    c1 = encrypt(m1, public_key)
    c2 = encrypt(m2, public_key)
    c = c1 * c2
    print("c' = c1*c2")
    result = decrypt(c, private_key, public_key)
    print("plaintext:" + str(result))

    print("###################################################")
    print("数乘同态验证")
    m3 = 16
    print("message3:" + str(m3))
    c3 = encrypt(m3, public_key)
    c = pow(c3, 4)
    print("c' = c^4")
    result = decrypt(c, private_key, public_key)
    print("plaintext:" + str(result))


if __name__ == "__main__":
    main()
