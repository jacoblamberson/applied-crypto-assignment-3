import random, sys
import hashlib
from Crypto.Util import number

NUM_TRIALS = 5


# Checks to see if a number is likely to be prime.
def is_prime(n):
    if n < 2:
        print("PANIC PANIC PANIC prime candidate less than 2")
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    s = 0
    d = n - 1
    while True:
        quotient, remainder = divmod(d, 2)
        if remainder == 1:
            break
        s += 1
        d = quotient

    def try_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2 ** i * d, n) == n - 1:
                return False
        return True

    for i in range(NUM_TRIALS):
        a = random.randrange(2, n)
        if try_composite(a):
            return False

    return True


# Right-to-left binary method
# A rip-off of Bruce Schneider's pseudocode
def my_modular_exp(base, exponent, modulus):
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base*base) % modulus
    return result


# Returns all prime numbers from start to stop, inclusive
def find_primes(start, stop):
    if start >= stop:
        print("Invalid range\n")
    if start % 2 == 0:
        start += 1
    primes = []

    for i in range(50):
        tmp_start = random.randrange(start, stop+1)
        for n in range(tmp_start, stop+1, 2):
            if is_prime(n) and n not in primes:
                primes.append(n)
                break
    #print(start)
    #print(stop)
    #print(primes)
    return primes


def relatively_prime(a, b):
    for n in range(2, min(a, b) + 1):
        if a % n == 0 and b % n == 0:
            return False
    return True


def get_bit_length_range(bit_length):
    min = 1 << (bit_length - 2)
    max = (1 << (bit_length + 1)) - 1
    return min, max


def get_prime_bit_length_range(bit_length):
    min = 1 << (bit_length - 1)
    max = (1 << bit_length) - 1
    return min, max


def get_bit_length(n):
    return len(bin(n))-2


def find_primes_for_bit_length_old(bit_length):
    #print(bit_length)
    n_min, n_max = get_bit_length_range(bit_length)
    p_min, p_max = get_bit_length_range(bit_length//2 + 1)
    primes = find_primes(p_min, p_max)
    while primes:
        p = random.choice(primes)
        primes.remove(p)
        q_candidates = [q for q in primes
                        if n_min <= p * q <= n_max]
        if q_candidates:
            q = random.choice(q_candidates)
            break
        #if not primes:
        #    primes = find_primes(p_min, p_max)
    else:
        return 0, 0
    return p, q


def find_primes_for_bit_length(bit_length):
    n_min, n_max = get_bit_length_range(bit_length)
    prime_bit_length = bit_length // 2
    while True:
        p = number.getPrime(prime_bit_length)
        q = number.getPrime(prime_bit_length)
        if n_min <= p * q <= n_max:
            return p, q


def choose_e(order):
    for e in range(3, order, 2):
        if relatively_prime(e, order):
            return e
    else:
        return 0


def choose_d(order, e):
    for i in range(1, order):
        tmp_check = ((order * i) + 1)
        if tmp_check % e == 0:
            divided = tmp_check // e
            return divided
    return 0


def generate_key_pair(bit_length):
    p, q = find_primes_for_bit_length(bit_length)
    n = p*q
    order = (p-1)*(q-1)

    e = choose_e(order)
    d = choose_d(order, e)
    return e, d, n


def encrypt(plaintext, e, n):
    return my_modular_exp(plaintext, e, n)


def decrypt(ciphertext, d, n):
    return my_modular_exp(ciphertext, d, n)


def get_random_bits(n):
    # THIS IS NOT SECURE RANDOMNESS, but I need determinism. Sorry not sorry.
    return random.getrandbits(n)


def get_r(n):
    sr = ""
    while len(sr) < n//4:
        tmp = int(get_random_bits(8))
        if tmp != 0:
            tmps = format(tmp, 'x')
            if len(tmps) == 1:
                tmps = '0' + tmps
            sr += tmps
    r = int(sr, 16)
    r = r & int('1' * n, 2)
    return r


# Included in case PKCS is desired
def construct_element_pkcs(m, N):
    n = get_bit_length(N)
    r_bit_length = n // 2
    m_bit_length = n // 2 - 24
    r = get_r(r_bit_length)

    element = m
    element = element ^ (r << (8 + m_bit_length))
    element = element ^ (2 << (r_bit_length + 8 + m_bit_length))

    return element


# Included in case PKCS is desired
def deconstruct_element_pkcs(element, N):
    n = get_bit_length(N)
    m_bit_length = n // 2 - 24
    m = element & int('1' * m_bit_length, 2)
    return m


def construct_element(m, N):
    n = get_bit_length(N)
    r_bit_length = n // 2
    m_bit_length = n // 2
    r = get_r(r_bit_length)

    element = m
    element = element ^ (r << m_bit_length)

    return element


def deconstruct_element(element, N):
    n = get_bit_length(N)
    m_bit_length = n // 2
    m = element & int('1' * m_bit_length, 2)
    return m


def pad_and_encrypt(m, e, N):
    element = construct_element(m, N)
    ciphertext = encrypt(element, e, N)
    return ciphertext


def decrypt_and_unpad(ciphertext, d, N):
    element = decrypt(ciphertext, d, N)
    plaintext = deconstruct_element(element, N)
    return plaintext


def sign_hash(hash, d, n):
    return encrypt(hash, d, n)


def make_hash(data):
    return int.from_bytes(hashlib.sha256(data).digest(), 'big')


def hash_and_sign(data, d, n):
    h = make_hash(data)
    sig = sign_hash(h, d, n)
    #print(h)
    #print(sig)
    #print("Validating")
    #validate_hash(sig, h, 3, n)
    return h, sig


def validate_hash(signature, h, e, n):
    decrypted = decrypt(signature, e, n)
    #print(h)
    #print(decrypted)
    return decrypted == h


def validate_signature(signature, data, e, n):
    h = make_hash(data)
    return validate_hash(signature, h, e, n)


input = ""
output = ""
keyfile = ""
public = ""
secret = ""
numBit = ""
function = ""
messagefile = ""

for a in range(1, len(sys.argv)):
    if sys.argv[a] == "-k":
        keyfile = sys.argv[a + 1]
    if sys.argv[a] == "-p":
        public = sys.argv[a + 1]
    if sys.argv[a] == "-o":
        output = sys.argv[a + 1]
    if sys.argv[a] == "-i":
        input = sys.argv[a + 1]
    if sys.argv[a] == "-s":
        secret = sys.argv[a + 1]
    if sys.argv[a] == "-n":
        numBit = sys.argv[a + 1]
    if sys.argv[a] == "-f":
        function = sys.argv[a + 1]
    if sys.argv[a] == "-m":
        messagefile = sys.argv[a + 1]

random.seed(1337)

if function == 'encrypt':
    keyring = open(keyfile, "r")
    keylist = keyring.readlines()
    keyring.close()
    infile = open(input, "r")
    inlist = infile.readlines()
    infile.close()
    n = int(keylist[0])
    N = int(keylist[1])
    e = int(keylist[2])
    plaintext = int(inlist[0])
    ciphertext = pad_and_encrypt(plaintext, e, N)
    outfile = open(output, "w")
    outfile.write(str(ciphertext) + '\n')
    outfile.close()
elif function == 'decrypt':
    keyring = open(keyfile, "r")
    keylist = keyring.readlines()
    keyring.close()
    infile = open(input, "r")
    inlist = infile.readlines()
    infile.close()
    n = int(keylist[0])
    N = int(keylist[1])
    d = int(keylist[2])
    ciphertext = int(inlist[0])
    plaintext = decrypt_and_unpad(ciphertext, d, N)
    outfile = open(output, "w")
    outfile.write(str(plaintext) + '\n')
    outfile.close()
elif function == 'keygen':
    n = int(numBit)
    e, d, N = generate_key_pair(n)
    sfile = open(secret, "w")
    sfile.write(str(n) + '\n')
    sfile.write(str(N) + '\n')
    sfile.write(str(d) + '\n')
    sfile.close()
    pfile = open(public, "w")
    pfile.write(str(n) + '\n')
    pfile.write(str(N) + '\n')
    pfile.write(str(e) + '\n')
    pfile.close()
    #print("Checking 123")
    #encrypted = encrypt(123, e, N)
    #decrypted = decrypt(encrypted, d, N)
    #print("Encrypted: " + str(encrypted))
    #print("Decrypted: " + str(decrypted))
    #encrypted = encrypt(123, d, N)
    #decrypted = decrypt(encrypted, e, N)
    #print("Encrypted: " + str(encrypted))
    #print("Decrypted: " + str(decrypted))
elif function == 'rsa-sign':
    keyring = open(keyfile, "r")
    keylist = keyring.readlines()
    keyring.close()
    infile = open(messagefile, "rb")
    message_data = infile.read()
    infile.close()
    n = int(keylist[0])
    N = int(keylist[1])
    d = int(keylist[2])
    h, sig = hash_and_sign(message_data, d, N)
    sig_file = open(secret, "w")
    sig_file.write(str(sig))
    sig_file.close()
elif function == 'rsa-validate':
    keyring = open(keyfile, "r")
    keylist = keyring.readlines()
    keyring.close()
    infile = open(messagefile, "rb")
    message_data = infile.read()
    infile.close()
    n = int(keylist[0])
    N = int(keylist[1])
    e = int(keylist[2])
    sig_file = open(secret, "r")
    sig = sig_file.readlines()
    sig_file.close()
    verdict = validate_signature(int(sig[0]), message_data, e, N)
    print(verdict)
else:
    print("BAD INPUT PANIC!!!")



exit()

#random.seed(1337)
print(is_prime(2))
print(is_prime(3))
print(is_prime(4))
print(is_prime(5))
print(is_prime(6))
print(is_prime(7))
e, d, N = generate_key_pair(60)
print((e, d, N))

# Encrypt ASCII '00'
print(encrypt(12336, e, N))
print(decrypt(encrypt(12336, e, N), d, N))

# Encrypt ASCII '0'
print(encrypt(48, e, N))

print(get_bit_length(7))
tmp = get_r(256)
print(tmp)
print(format(tmp, 'x'))
print(format(tmp << 8*2, 'x'))
print(format(construct_element(int('beef', 16), int('1000000000000', 16)), 'x'))
#print(get_bit_length(10000000000000000000000000))
print(format(279936, 'x'))
print(pow(12, 2, 623))
print(my_modular_exp(12, 2, 623))

#print(is_prime(1))
print(is_prime(2))
print(is_prime(3))
print(is_prime(4))
print(is_prime(5))
print(is_prime(6))
print(is_prime(7))