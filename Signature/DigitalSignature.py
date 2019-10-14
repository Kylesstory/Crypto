from Essential import Utilities as utils
import abc

class DigitalSignature(object):
	"""docstring for DigitalSignature"""
	def __init__(self, arg):
		raise NotImplementedError("DigitalSignature is abstract.")
	
	@abc.abstractmethod
	def sign(self, m):
		pass
	
	@abc.abstractmethod
	def verify(self, c):
		pass

class RSA(DigitalSignature):
	"""docstring for RSA"""
	def __init__(self, security):
		self.security = security
		self.n, p2q2 = utils.composeOrder(security)
		_lambda = p2q2 << 1
		self.e = utils.coPrime(security - 1, _lambda)
		self.d = utils.modinv(self.e, _lambda)
		
	def sign(self, m):
		return pow(utils.hash(m, self.security), self.d, self.n)

	def verify(self, m, s):
		return pow(s, self.e, self.n) == utils.hash(m, self.security)

	def demo(self, message):
		s = self.sign(message)
		param = {'security': self.security, 'n': self.n, 'd': self.d, 'e': self.e, 'message': message, 'signature': s, 'verification': self.verify(message, s)}
		utils.colorfulPrint('RSA signature', param)
		
class DSA(DigitalSignature):
	"""docstring for DSA"""
	def __init__(self, security):
		self.security = security
		self.p, self.q, self.g = utils.primeOrder(security)
		self.sk, self.pk = utils.dlPair(security, self.g, self.q, self.p)

	def sign(self, m):
		r = s = 0
		while r == s or s == 0:
			while r == s or r == 0:
				k = utils.randomBits(self.security) % self.q
				r = pow(self.g, k, self.p) % self.q
			s = (utils.modinv(k, self.q) * (utils.hash(m, self.security) + self.sk * r)) % self.q
		return [r, s]

	def verify(self, m, sig):
		r = sig[0]
		s = sig[1]
		assert r > 0 and r < self.q and s > 0 and s < self.q
		w = utils.modinv(s, self.q)
		gk = ((pow(self.g, utils.hash(m, self.security) * w, self.p) * pow(self.pk, r * w, self.p)) % self.p) % self.q
		return (r == gk)

	def demo(self, message):
		s = self.sign(message)
		param = {'security': self.security, 'g': self.g, 'q': self.q, 'p': self.p, 'sk': self.sk, 'pk': self.pk, 'message': message, 'signature': s, 'verification': self.verify(message, s)}
		utils.colorfulPrint('DSA signature', param)
	