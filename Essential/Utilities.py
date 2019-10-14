import hashlib, colorama
from random import randrange, getrandbits
from colorama import Fore

def hash(x, length):
	s = ''.join([str(i) for i in x]) if isinstance(x, list) else str(x)
	x = hashlib.sha3_256(s.encode('utf-8')).hexdigest()
	h = ''
	length = int(length / 4)
	while len(h) <= length: h = h + str(x)
	return int(h[:length], 16)

def randomBits(bits):
	return getrandbits(bits)

### referred to Märt Bakhoff
### https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        return -1 # slightly modified here from original program
    else:
        return x % m

### referred to Antoine Prudhomme
### https://medium.com/@prudywsh/how-to-generate-big-prime-numbers-miller-rabin-49e6e6af32fb
def is_prime(n, k = 128):
    """ Test if a number is prime
        Args:
            n -- int -- the number to test
            k -- int -- the number of tests to do
        return True if n is prime
    """
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True

def generate_prime_candidate(length):
    """ Generate an odd integer randomly
        Args:
            length -- int -- the length of the number to generate, in bits
        return a integer
    """
    # generate random bits
    p = getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=1024):
    """ Generate a prime
        Args:
            length -- int -- length of the prime to generate, in          bits
        return a prime
    """
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p

def strongPrime(security): # return a pair of primes p, q s.t. p = 2q + 1 
	p = q = 4
	while not is_prime(p, 128):
		q = generate_prime_number(security - 1)
		p = (q << 1) + 1
	return p, q

def composeOrder(security): # return n and p2q2 as a compose order group
	p, p2 = strongPrime(int(security / 2))
	q = p
	while (q == p): q, q2 = strongPrime(int(security / 2))
	return p * q, p2 * q2

def primeOrder(security): # return p, q, g as a prime order group
	p, q = strongPrime(security)
	return p, q, coPrime(security, p, q)

def coPrime(security, n, q = 0): # find a number g coprime to modular
	g = 1
	while (g == 1) or (egcd(g, n)[0] != 1) or ((q > 1) and (pow(g, q, n) != 1)):
		g = randomBits(security) % n
	return g

def dlPair(security, g, q, p): # find x and g^x
	x = 0
	while x == 0: x = randomBits(security) % q
	return x, pow(g, x, p)

def colorfulPrint(header, data):
	print('%s {' % (header))
	keys = [*data]
	for key in keys:
		if isinstance(data[key], list):
			print('  %s: [' % key)
			for d in data[key]:
				print('    %s%s' % (colorfulTypes(d), ',' if d != data[key][-1] else ''))
			print('  ]')
		else:
			print('  %s: %s%s' % (key, colorfulTypes(data[key]), ',' if (key != keys[-1]) else ''))
	print('}\n')

def colorfulTypes(raw):
	if isinstance(raw, bool):
		return '%s%s%s' % (Fore.YELLOW, str(raw), Fore.RESET)
	if isinstance(raw, int):
		if raw < 100000: # for small numbers
			return '%s%d%s' % (Fore.YELLOW, raw, Fore.RESET)
		else:
			raw = hex(raw)[2:]
	if isinstance(raw, str):
		return '%s\'%s\'%s' % (Fore.GREEN, raw, Fore.RESET)