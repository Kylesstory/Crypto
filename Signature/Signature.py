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

	def sign(self, sk, pk, m):
		return exp(Hash.hash3_256([m], self.security), sk, pk[1])

	def verify(self, pk, m, sig):
		return exp(sig, pk[0], pk[1]) == Hash.hash3_256([m], self.security)

class DSA(object):
	"""docstring for DSA"""
	def __init__(self, para):
		super(DSA, self).__init__()
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

	def sign(self, sk, pk, m):
		r = s = 0
		while s == 0:
			while r == 0:
				k = random.getrandbits(self.security) % self.q
				r = exp(self.g, k, self.p) % self.q
			s = (ModInv.modinv(k, self.q) * (Hash.hash3_256([m], self.security) + sk * r)) % self.q
		return [r, s]

	def verify(self, pk, m, sig):
		r = sig[0]
		s = sig[1]
		assert r > 0 and r < self.q and s > 0 and s < self.q
		w = ModInv.modinv(s, self.q)
		u1 = (Hash.hash3_256([m], self.security) * w) % self.q
		u2 = (r * w) % self.q
		return (r == (((exp(self.g, u1, self.p) * exp(pk, u2, self.p))% self.p) % self.q))