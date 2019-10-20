from Essential import Utilities as utils
import abc

class PKEncryption(object):
	"""Public Key Encryptions"""
	def __init__(self, arg):
		""" The key (secret key / public key) generation algorithm. """
		raise NotImplementedError("PKEncryption is abstract.")
	
	@abc.abstractmethod
	def encrypt(self,m):
		""" The sender encrypts a message m using the public key and 
		output a ciphertext c. """
		raise NotImplementedError("The encryption algorithm has not been implemented.")
	
	@abc.abstractmethod
	def decrypt(self, c):
		""" The receiver decrypts a ciphertext c and outputs a message m 
		using the secret key. """
		raise NotImplementedError("The decryption algorithm has not been implemented.")

	def demo(self, message):
		c = self.encrypt(message)
		m = self.decrypt(c)
		self.params['message'] = message
		self.params['encrypted'] = c
		self.params['decrypted'] = m
		self.params['success'] = (message == m)
		utils.show(self.name, self.params)

class RSA(PKEncryption):
	def __init__(self, security):
		self.security = security
		self.n, p2q2 = utils.composeOrder(security)
		_lambda = p2q2 << 1
		self.e = utils.coPrime(security, _lambda)
		self.d = utils.modinv(self.e, _lambda)
		self.name = 'RSA encryption'
		self.params = {'security': security, 'n': self.n, 'd': self.d, 'e': self.e}

	def encrypt(self, m):
		return pow(m, self.e, self.n)

	def decrypt(self, c):
		return pow(c, self.d, self.n)

	def add(self, c1, c2):
		return (c1 * c2) % self.n

class ElGamal(PKEncryption):
	def __init__(self, security):
		self.security = security
		self.p, self.q, self.g = utils.primeOrder(security)
		self.x, self.y = utils.dlPair(security, self.g, self.q, self.p)
		self.name = 'ElGamal encryption'
		self.params = {'security': security, 'g': self.g, 'q': self.q, 'p': self.p, 'sk': self.x, 'pk': self.y}

	def encrypt(self, m):
		r, c1 = utils.dlPair(self.security, self.g, self.q, self.p)
		c2 = (m * pow(self.y, r, self.p)) % self.p
		return [c1, c2]

	def decrypt(self, c):
		return utils.divide(c[1], pow(c[0], self.x, self.p), self.p)

	def multiply(self, pk, c1, c2):
		return [(c1[0] * c2[0]) % self.p, (c1[1] * c2[1]) % self.p]


class Paillier(PKEncryption):
	def __init__(self, security):
		self.security = security
		self.n, self.sk = utils.composeOrder(security)
		self.n2 = self.n * self.n
		x = utils.randomBits(security, self.n)
		self.g = 1 + x * self.n
		self.name = 'Paillier encryption'
		self.params = {'security': security, 'n': self.n, 'sk': self.sk, 'g': self.g}

	def encrypt(self, m):
		r = utils.randomBits(self.security << 1, self.n2)
		return (pow(self.g, m, self.n2) * pow(r, 2 * self.n, self.n2)) % self.n2

	def decrypt(self, c):
		x = self.L(pow(c, self.sk, self.n2))
		y = self.L(pow(self.g, self.sk, self.n2))
		return utils.divide(x, y, self.n)

	def add(self, c1, c2):
		return (c1 * c2) % self.n2

	def multiply(self, c, a):
		return pow(c, a, self.n2)

	def L(self, x):
		return (x - 1) // self.n

class CramerShoup(PKEncryption):
	def __init__(self, security):
		self.security = security
		self.p, self.q, self.g = utils.primeOrder(security)
		self.h = self.g
		while self.h == self.g:
			self.h = utils.coPrime(security, self.p, self.q)
		self.sk = [utils.randomBits(security - 1, self.q) for i in range(5)]
		self.c = pow(self.g, self.sk[0], self.p) * pow(self.h, self.sk[1], self.p) % self.p
		self.d = pow(self.g, self.sk[2], self.p) * pow(self.h, self.sk[3], self.p) % self.p
		self.y = pow(self.g, self.sk[4], self.p)
		self.name = 'Cramer-Shoup encryption'
		self.params = {'security': security, 'g': self.g, 'q': self.q, 'p': self.p, 'h': self.h, 'sk': self.sk, 'pk': [self.c, self.d, self.y]}

	def encrypt(self, m):
		r = utils.randomBits(self.security, self.q) 
		u = pow(self.g, r, self.p)
		v = pow(self.h, r, self.p)
		w = m * pow(self.y, r, self.p) % self.p
		h = utils.hash([u, v, w], self.security, self.q)
		t = (self.c * pow(self.d, h, self.p)) % self.p
		x = pow(t, r, self.p)
		return [u, v, w, x]

	def decrypt(self, c):
		h = utils.hash([c[0], c[1], c[2]], self.security, self.q)
		t = (pow(c[0], ((self.sk[0] + self.sk[2] * h) % self.q) , self.p) * pow(c[1], ((self.sk[1] + self.sk[3] * h) % self.q), self.p)) % self.p
		assert c[3] == t
		return utils.divide(c[2], pow(c[0], self.sk[4], self.p), self.p)
