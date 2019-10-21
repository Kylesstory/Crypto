from Essential import Utilities as utils
from ZeroKnowledgeProof import ZKP
import abc

class NIZK(object):
	"""Zero-knowledge proofs"""
	def __init__(self, security, trust):
		raise NotImplementedError("NIZK is abstract.")
	
	@abc.abstractmethod
	def commit(self, x):
		""" The prover outputs a commit in the beginning of ZKP. """
		raise NotImplementedError("The commit algorithm has not been implemented.")

	@abc.abstractmethod
	def request(self):
		""" The prover outputs requests in the proving phase of ZKP. """
		raise NotImplementedError("The request algorithm has not been implemented.")

	@abc.abstractmethod
	def challenge(self, com, req):
		""" The main difference from zero knowledge and NIZK. The Fiat-Shamir transfer 
		makes all ZKP algorithms non-interactive, as NIZK algorithms. The prover generates 
		a challenge chg on input a commitment com and a request req. """
		raise NotImplementedError("The challenge algorithm has not been implemented.")

	@abc.abstractmethod
	def response(self, req, chg):
		""" The prover responses on receiving a challenge chg 
		related to a request req. """
		raise NotImplementedError("The response algorithm has not been implemented.")

	@abc.abstractmethod
	def verify(self, com, req, chg, res):
		""" The verifier verifies the commitment com with a request req 
		a challenge chg, and its response res; and then outputs its validity True or False. """
		raise NotImplementedError("The verification algorithm has not been implemented.")

	@abc.abstractmethod
	def demonstrate(self, message):
		""" The demo algorithm of NIZK algorithms is implemented in ZKP.demo(). """
		com = self.commit(message)
		req = self.request()
		chg = self.challenge(com, req)
		res = self.response(req, chg)
		valid = self.verify(com, req, chg, res)
		self.params['secret'] = message
		self.params['commitment'] = com
		self.params['request'] = req
		self.params['challenge'] = chg
		self.params['response'] = res
		self.params['verification'] = valid
		self.params.pop('confidence', None)
		utils.show('%s NIZK proof' % self.name, self.params)

class Schnorr(ZKP.Schnorr, NIZK): 
	""" Single value x that x is not a very small number. """
	def __init__(self, security):
		super(Schnorr, self).__init__(security, security)

	def challenge(self, com, req):
		return utils.hash([com, req], self.security, self.p)

	def demo(self, message):
		super(Schnorr, self).demonstrate(message)

class GuillouQuisquater(ZKP.GuillouQuisquater, NIZK): 
	""" Single value x that x is not a very small number. """
	def __init__(self, security):
		super(GuillouQuisquater, self).__init__(security, security)

	def challenge(self, com, req):
		return utils.hash([com, req], self.security, self.order)

	def demo(self, message):
		super(GuillouQuisquater, self).demonstrate(message)

class ChaumPedersen(ZKP.ChaumPedersen, NIZK):
	""" To proof a value com is a square number of root x. """
	def __init__(self, security):
		super(ChaumPedersen, self).__init__(security, security)

	def challenge(self, com, req):
		return utils.hash([com[0], com[1], req[0], req[1]], self.security, self.q)

	def demo(self, message):
		super(ChaumPedersen, self).demonstrate(message)