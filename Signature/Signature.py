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