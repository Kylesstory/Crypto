from Essential import Utilities as utils
import abc

class Commitment(object):
	"""docstring for Commitment"""
	def __init__(self, arg):
		raise NotImplementedError("DigitalSignature is abstract.")
	
	@abc.abstractmethod
	def commit(self, m):
		pass

	def open(self):
		return self.m, self.r
	
	@abc.abstractmethod
	def verify(self, c):
		pass		

class HashCommit(Commitment):
	"""docstring for HashCommit"""
	def __init__(self, security):
		self.security = security

	def commit(self, m):
		self.m = m
		self.r = utils.randomBits(self.security)
		return utils.hash([self.m, self.r], self.security)

	def verify(self, m, r, com):
		return com == utils.hash([m, r], self.security)

	def demo(self, message):
		com = self.commit(message)
		m, r = self.open()
		params = {'security': self.security, 'message': m, 'randomness': r, 'commitment': com, 'verification': self.verify(m, r, com)}
		utils.colorfulPrint('Hash commitment', params)

class Pederson(Commitment):
	def __init__(self, security):
		self.security = security
		self.p, self.q, self.g = utils.primeOrder(security)
		self.h = utils.generator(security, self.p)

	def commit(self, m):
		self.m = m
		self.r = utils.randomBits(self.security) % self.q
		return (pow(self.g, m, self.p)) * (pow(self.h, self.r, self.p)) % self.p

	def verify(self, m, r, com):
		return com == ((pow(self.g, m, self.p)) * (pow(self.h, r, self.p)) % self.p)

	def homomorphicAdd(self, c1, c2):
		return (c1 * c2) % self.p

	def demo(self, message):
		com = self.commit(message)
		m, r = self.open()
		params = {'security': self.security, 'p': self.p, 'q': self.q, 'g': self.g, 'h': self.h, 'message': m, 'randomness': r, 'commitment': com, 'verification': self.verify(m, r, com)}
		utils.colorfulPrint('Pederson commitment', params)
