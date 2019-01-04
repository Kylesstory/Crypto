import random
from Essential import BigPrime, ModInv, Hash
from math import gcd

def exp(g, e, m): return pow(g, e, m)

class RSA(object):
	"""docstring for RSA"""
	def __init__(self, para):
		super(RSA, self).__init__()
		self.para = para
		self.security = para['security']
		self.description = 'secure length:\t%d' % para['security']
		self.bonus = ['Homomorphically multiply two ciphertext']

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
		return exp(c, sk, pk[1])

	def homomorphic(self, pk, c1, c2):
		return (c1 * c2) % pk[1]

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
		self.bonus = ['Homomorphically multiply two ciphertext']

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

	def homomorphic(self, pk, c1, c2):
		return [(c1[0] * c2[0]) % self.p, (c1[1] * c2[1]) % self.p]

class Paillier(object):
	"""docstring for Paillier"""
	def __init__(self, para):
		super(Paillier, self).__init__()
		self.para = para
		self.security = para['security']
		self.description = 'secure length:\t%d' % para['security']
		self.bonus = ['Homomorphically add two ciphertext']

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

	def homomorphic(self, pk, c1, c2):
		return (c1 * c2) % (pk[1] * pk[1])

	def L(self, x, n):
		return int((x - 1) / n)

class CramerShoup(object):
	"""docstring for CramerShoup"""
	def __init__(self, para):
		super(CramerShoup, self).__init__()
		self.para = para
		if not para['q']: # no previous stored data
			para['p'] = 4
			while not BigPrime.is_prime(para['p']):
				para['q'] = BigPrime.generate_prime_number(para['security'])
				para['p'] = (para['q'] << 1) + 1
			para['g'] = random.getrandbits(para['security']) % para['p']
			para['h'] = random.getrandbits(para['security']) % para['p']
		self.para = para
		self.security = para['security']
		self.p = para['p']
		self.g = para['g']
		self.h = para['h']
		self.q = para['q']
		self.description = 'secure length:\t%d\ngenerator 1:\t%d\ngenerator 2:\t%d\nmodular:\t%d\norder:\t\t%d\nhash function: \tthe MSB [security] bits of repeated SHA3-256 hash function results.' % (para['security'], para['g'], para['h'], para['p'], para['q'])
		self.bonus = None

	def keyGenerate(self):
		sk = [random.getrandbits(self.security) % self.q for i in range(5)]
		c = exp(self.g, sk[0], self.p) * exp(self.h, sk[1], self.p) % self.p
		d = exp(self.g, sk[2], self.p) * exp(self.h, sk[3], self.p) % self.p
		y = exp(self.g, sk[4], self.p)
		return sk, [c, d, y]

	def encrypt(self, pk, m):
		r = random.getrandbits(self.security) % self.q 
		u = exp(self.g, r, self.p)
		v = exp(self.h, r, self.p)
		w = m * exp(pk[2], r, self.p) % self.p

		h = Hash.hash3_256([u, v, w], self.security)
		t = (pk[0] * exp(pk[1], h, self.p)) % self.p
		x = exp(t, r, self.p)
		return [u, v, w, x]

	def decrypt(self, sk, pk, c):
		h = Hash.hash3_256([c[0], c[1], c[2]], self.security)
		t = (exp(c[0], ((sk[0] + sk[2] * h) % self.q) , self.p) * exp(c[1], ((sk[1] + sk[3] * h) % self.q), self.p)) % self.p
		m = (c[2] * ModInv.modinv(exp(c[0], sk[4], self.p), self.p)) % self.p
		assert c[3] == t
		return m
	
