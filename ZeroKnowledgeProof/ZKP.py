# -*- coding: utf-8 -*-
"""
.. module:: ZKP
   :synopsis: The zero-knowledge proof.
.. moduleauthor:: Kyle
"""

from Essential import Groups, Utilities as utils
import abc


class ZeroKnowledgeProof(object):
    """Zero-knowledge proofs"""

    def __init__(self, security, confidence):
        raise NotImplementedError("ZeroKnowledgeProof is abstract.")

    @abc.abstractmethod
    def commit(self, x):
        # The prover outputs a commit in the beginning of ZKP.
        raise NotImplementedError(
            "The commit algorithm has not been implemented.")

    @abc.abstractmethod
    def request(self):
        # The prover outputs requests in the proving phase of ZKP.
        raise NotImplementedError(
            "The request algorithm has not been implemented.")

    @abc.abstractmethod
    def challenge(self, com, req):
        # The verifier generates a challenge chg on input a
        # commitment com and a request req.
        raise NotImplementedError(
            "The challenge algorithm has not been implemented.")

    @abc.abstractmethod
    def response(self, req, chg):
        # The prover responses on receiving a challenge chg.
        # related to a request req.
        raise NotImplementedError(
            "The response algorithm has not been implemented.")

    @abc.abstractmethod
    def verify(self, com, req, chg, res):
        # The verifier verifies the commitment com with a request req
        # a challenge chg, and its response res; and then outputs its
        # validity True or False.
        raise NotImplementedError(
            "The verification algorithm has not been implemented.")

    def demo(self, message):
        com = self.commit(message)
        queries = []
        allValid = True
        for _ in range(self.confidence):
            req = self.request()
            chg = self.challenge(com, req)
            res = self.response(req, chg)
            valid = self.verify(com, req, chg, res)
            queries.append({'request': req, 'challenge': chg,
                            'response': res, 'verified': valid})
            allValid = (allValid and valid)
        self.params['secret'] = message
        self.params['commitment'] = com
        self.params['proofs'] = queries
        self.params['verification'] = allValid
        utils.show('%s zero-knowledge proof' % self.name, self.params)


class Schnorr(Groups.PrimeOrder, ZeroKnowledgeProof):
    """ Single value x that x is not a very small number. """

    def __init__(self, security, confidence):
        super(Schnorr, self).__init__(security, False, 'Schnorr\'s')
        self.params['confidence'] = self.confidence = confidence
        self.randomness = {}

    def commit(self, x):
        self.x = x
        return pow(self.g, x, self.p)

    def request(self):
        r = utils.random_bits(self.security, self.q)
        R = pow(self.g, r, self.p)
        self.randomness[R] = r
        return R

    def challenge(self, com, req):
        return utils.random_bits(self.security, self.q)

    def response(self, req, chg):
        r = self.randomness[req]
        return ((self.x * chg + r) % self.q)

    def verify(self, com, req, chg, res):
        y = pow(self.g, res, self.p)
        return (y == (pow(com, chg, self.p) * req % self.p))


class GuillouQuisquater(Groups.RSA, ZeroKnowledgeProof):
    """ Single value x that x is not a very small number. """

    def __init__(self, security, confidence):
        super(GuillouQuisquater, self).__init__(security)
        self.params['confidence'] = self.confidence = confidence
        self.params['order'] = self.order = self.p2q2 << 1
        self.name = 'Guillou-Quisquater'
        self.randomness = {}

    def commit(self, x):
        self.x = x
        return pow(x, self.e, self.n)

    def request(self):
        r = utils.coprime(self.security, self.order)
        R = pow(r, self.e, self.n)
        self.randomness[R] = r
        return R

    def challenge(self, com, req):
        return utils.random_bits(self.security, self.order)

    def response(self, req, chg):
        r = self.randomness[req]
        return ((pow(self.x, chg, self.n) * r) % self.n)

    def verify(self, com, req, chg, res):
        y = pow(res, self.e, self.n)
        return (y == (pow(com, chg, self.n) * req % self.n))


class FiatShamir(Groups.CompositeOrder, ZeroKnowledgeProof):
    """ To proof a value com is a square number of root x. """

    def __init__(self, security, confidence):
        super(FiatShamir, self).__init__(security, 'Fiat-Shamir')
        self.params['confidence'] = self.confidence = confidence
        self.randomness = {}

    def commit(self, x):
        self.x = x
        return pow(x, 2, self.n)

    def request(self):
        r = utils.random_bits(self.security, self.n)
        R = pow(r, 2, self.n)
        self.randomness[R] = r
        return R

    def challenge(self, com, req):
        return utils.random_bits(1)

    def response(self, req, chg):
        r = self.randomness[req]
        return ((self.x * r) % self.n) if chg == 1 else r

    def verify(self, com, req, chg, res):
        y = pow(res, 2, self.n)
        return (y == (com * req % self.n)) if chg == 1 else (y == req)


class ChaumPedersen(Groups.PrimeOrder, ZeroKnowledgeProof):
    """ The Pedersen commitment based ZKP algorithms. """

    def __init__(self, security, confidence):
        super(ChaumPedersen, self).__init__(security, True, 'Chaum-Pedersen')
        self.params['confidence'] = self.confidence = confidence
        self.randomness = {}

    def commit(self, x):
        self.x = x
        return [pow(self.g, x, self.p), pow(self.h, x, self.p)]

    def request(self):
        r = utils.random_bits(self.security, self.q)
        R1 = pow(self.g, r, self.p)
        R2 = pow(self.h, r, self.p)
        self.randomness[R1] = self.randomness[R2] = r
        return [R1, R2]

    def challenge(self, com, req):
        return utils.random_bits(self.security, self.q)

    def response(self, req, chg):
        assert self.randomness[req[0]] == self.randomness[req[1]]
        r = self.randomness[req[0]]
        return ((self.x * chg + r) % self.q)

    def verify(self, com, req, chg, res):
        y1 = pow(self.g, res, self.p)
        y2 = pow(self.h, res, self.p)
        return (y1 == (req[0] * pow(com[0], chg, self.p) % self.p)
                and y2 == (req[1] * pow(com[1], chg, self.p) % self.p))
