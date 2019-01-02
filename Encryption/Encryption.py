import random
from Essencial import BigPrime, ModInv
from math import gcd

def exp(g, e, m):
	return pow(g, e, m)

class RSA(object):
	"""docstring for RSA"""
	def __init__(self, para):
		super(RSA, self).__init__()
		self.para = para
		self.security = para['security']
		self.description = 'secure length:\t%d' % para['security']
										
	def keyGenerate(self):
		p = BigPrime.generate_prime_number(int(self.security / 2))
		q = BigPrime.generate_prime_number(int(self.security / 2))
		n = p * q
		_lambda = int((p - 1) * (q - 1) / gcd(p - 1, q - 1))
		while True:
			e = random.getrandbits(self.security) % _lambda
			d = ModInv.modinv(e, _lambda)
			if d != -1: break
		return d, [e, n]

	def encrypt(self, pk, m):
		return exp(m, pk[0], pk[1])

	def decrypt(self, sk, pk, c):
		return exp(c, sk[0], pk[1])

class ElGamal(object):
	"""docstring for ElGamal"""
	def __init__(self, para):
		super(ElGamal, self).__init__()
		if not para['q']: # no previous stored data
			para['p'] = 4
			while not BigPrime.is_prime(para['p']):
				para['q'] = BigPrime.generate_prime_number(para['security'])
				para['p'] = (para['q'] << 1) + 1
			para['g'] = random.getrandbits(para['security']) % para['p']
		self.para = para
		self.security = para['security']
		self.p = para['p']
		self.g = para['g']
		self.q = para['q']
		self.description = 'secure length:\t%d\ngenerator:\t%d\nmodular:\t%d\norder:\t\t%d' % (para['security'], para['g'], para['p'], para['q'])

	def keyGenerate(self):
		sk = 0
		pk = 1
		while pk == 1: 
			sk = random.getrandbits(self.security) % self.q
			pk = exp(self.g, sk, self.p)
		return sk, pk

	def encrypt(self, pk, m):
		r = random.getrandbits(self.security) % self.q
		c1 = exp(self.g, r, self.p)
		c2 = (m * exp(pk, r, self.p)) % self.p
		return [c1, c2]

	def decrypt(self, sk, pk, c):
		return c[1] * ModInv.modinv(exp(c[0], sk, self.p), self.p) % self.p

class Paillier(object):
	"""docstring for Paillier"""
	def __init__(self, para):
		super(Paillier, self).__init__()
		self.para = para
		self.security = para['security']
		self.description = 'secure length:\t%d' % para['security']

	def keyGenerate(self):
		p = BigPrime.generate_prime_number(int(self.security / 2))
		q = BigPrime.generate_prime_number(int(self.security / 2))
		n = p * q
		_lambda = int((p - 1) * (q - 1) / gcd(p - 1, q - 1))
		g = random.getrandbits(2 * self.security) % (n * n)
		return _lambda, [g, n]

	def encrypt(self, pk, m):
		n2 = pk[1] * pk[1]
		r = random.getrandbits(2 * self.security) % n2
		return (exp(pk[0], m, n2) * exp(r, pk[1], n2)) % n2

	def decrypt(self, sk, pk, c):
		n2 = pk[1] * pk[1]
		c1 = self.L(exp(c, sk, n2), pk[1])
		c2 = self.L(exp(pk[0], sk, n2), pk[1])
		return (c1 * ModInv.modinv(c2, n2)) % pk[1]

	def L(self, x, n):
		return int((x - 1) / n)
		