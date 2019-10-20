from Commitment.Commitment import Pedersen
from Essential import Utilities as utils
import abc

class ZeroKnowledgeProof(object):
	"""docstring for ZeroKnowledgeProof"""
	def __init__(self, security, trust):
		raise NotImplementedError("ZeroKnowledgeProof is abstract.")
	
	@abc.abstractmethod
	def commit(self, x):
		""" The prover outputs a commit in the beginning of ZKP. """
		raise NotImplementedError("The commitment algorithm has not been implemented.")

	@abc.abstractmethod
	def proof(self):
		""" The prover outputs proofs in the proving phase of ZKP. """
		raise NotImplementedError("The proof algorithm has not been implemented.")

	@abc.abstractmethod
	def challenge(self, com, proof):
		""" The verifier generates a challenge request req on input a commitment com and a proof. """
		raise NotImplementedError("The challenge algorithm has not been implemented.")

	@abc.abstractmethod
	def response(self, proof, req):
		""" The prover responses on receiving a challenge request req 
		related to a proof. """
		raise NotImplementedError("The response algorithm has not been implemented.")

	@abc.abstractmethod
	def verify(self, com, proof, req, res):
		""" The verifier verifies the commitment com with the challenge 
		request req and its response res; and then outputs its validity True or False. """
		raise NotImplementedError("The verification algorithm has not been implemented.")

	def demo(self, message):
		com = self.commit(message)
		queries = []
		allValid = True
		for _ in range(self.trust):
			proof = self.proof()
			req = self.challenge(com, proof)
			res = self.response(proof, req)
			valid = self.verify(com, proof, req, res)
			queries.append({'proof': proof, 'req': req, 'res': res, 'verified': valid})
			allValid = (allValid and valid)
		self.params['secret'] = message
		self.params['commitment'] = com
		self.params['challenges'] = queries
		self.params['verification'] = allValid
		utils.show('%s zero-knowledge proof' % self.name, self.params)

class SingleValue(ZeroKnowledgeProof): 
	""" Single value x that x is not a very small number. """
	def __init__(self, security, trust):
		self.security = security
		self.trust = trust
		self.p, self.q, self.g = utils.primeOrder(security)
		self.proofs = {}
		self.name = 'Single value'
		self.params = {'security': security, 'false positive probability': '2 ^ (-%d)' % self.trust, 'p': self.p, 'q': self.q, 'g': self.g}

	def commit(self, x):
		self.x = x
		return pow(self.g, x, self.p)

	def proof(self):
		r = utils.randomBits(self.security, self.q) 
		R = pow(self.g, r, self.p)
		self.proofs[R] = r
		return R

	def challenge(self, com, proof):
		return utils.randomBits(1)

	def response(self, proof, req):
		r = self.proofs[proof]
		return ((self.x + r) % self.q) if req == 1 else r

	def verify(self, com, proof, req, res):
		y = pow(self.g, res, self.p)
		return (y == (com * proof % self.p)) if req == 1 else (y == proof)

class FiatShamir(ZeroKnowledgeProof):
	""" To proof a value com is a square number of root x. """
	def __init__(self, security, trust):
		self.security = security
		self.trust = trust
		self.n, _ = utils.composeOrder(security)
		self.proofs = {}
		self.name = 'Fiat-Shamir'
		self.params = {'security': security, 'false positive probability': '2 ^ (-%d)' % self.trust, 'n': self.n}
		
	def commit(self, x):
		self.x = x
		return pow(x, 2, self.n)

	def proof(self):
		r = utils.randomBits(self.security, self.n) 
		R = pow(r, 2, self.n)
		self.proofs[R] = r
		return R

	def challenge(self, com, proof):
		return utils.randomBits(1)

	def response(self, proof, req):
		r = self.proofs[proof]
		return ((self.x * r) % self.n) if req == 1 else r

	def verify(self, com, proof, req, res):
		y = pow(res, 2, self.n)
		return (y == (com * proof % self.n)) if req == 1 else (y == proof)

class ChaumPedersen(ZeroKnowledgeProof):
	""" The Pedersen commitment based ZKP algorithms. """
	def __init__(self, security, trust):
		self.security = security
		self.trust = trust
		self.committer = Pedersen(security)
		self.p = self.committer.p
		self.q = self.committer.q
		self.g = self.committer.g
		self.h = self.committer.h
		self.proofs = {}
		self.name = 'Chaum-Pedersen'
		self.params = {'security': security, 'p': self.p, 'q': self.q, 'g': self.g, 'h': self.h}

	def commit(self, x):
		com = self.committer.commit(x)
		self.proofs[com] = self.committer.open()
		return com
	
	