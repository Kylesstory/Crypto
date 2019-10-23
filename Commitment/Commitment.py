# -*- coding: utf-8 -*-
"""
.. module:: Commitment
   :synopsis: The cryptographic commitment.
.. moduleauthor:: Kyle
"""

from Essential import Groups, Utilities as utils
import abc


class Commitment(object):
    """Cryptographic Commitment"""

    def __init__(self, arg):
        raise NotImplementedError("DigitalSignature is abstract.")

    @abc.abstractmethod
    def commit(self, m):
        """ The prover inputs a message m, it outputs commitment com 
        corresponding to m and a random number r; and the later two 
        parameters are kept secret in this phase. """
        raise NotImplementedError(
            "The commitment algorithm has not been implemented.")

    def open(self):
        """ The prover opens the message m and the randomness r to 
        the verifier where m and r were kept in the previous phase. """
        return self.m, self.r

    @abc.abstractmethod
    def verify(self, m, r, com):
        """ The verifier verifies the message m, the randomness r and 
        the commitment com and returns its validity. """
        raise NotImplementedError(
            "The verification algorithm has not been implemented.")

    def demo(self, message):
        com = self.commit(message)
        m, r = self.open()
        self.params['message'] = m
        self.params['randomness'] = r
        self.params['commitment'] = com
        self.params['verification'] = self.verify(m, r, com)
        utils.show('%s commitment' % self.name, self.params)


class HashCommit(Commitment):
    def __init__(self, security):
        self.security = security
        self.name = 'Hash-based'
        self.params = {'security': security}

    def commit(self, m):
        self.m = m
        self.r = utils.random_bits(self.security)
        return utils.hash([self.m, self.r], self.security)

    def verify(self, m, r, com):
        return com == utils.hash([m, r], self.security)


class RSA(Groups.RSA, Commitment):
    def __init__(self, security):
        super(RSA, self).__init__(security)
        self.params['g'] = self.g = utils.coprime(security, self.n)

    def commit(self, m):
        self.m = m
        self.r = utils.random_bits(self.security, self.n)
        return (pow(self.g, m, self.n) * pow(self.r, self.e, self.n)) % self.n

    def verify(self, m, r, com):
        return (com == (pow(self.g, m, self.n) * pow(r, self.e, self.n))
                % self.n)

    def add(self, c1, c2):
        return (c1 * c2) % self.n


class ElGamal(Groups.PrimeOrder, Commitment):
    def __init__(self, security):
        super(ElGamal, self).__init__(security, True, 'ElGamal')

    def commit(self, m):
        self.m = m
        self.r = utils.random_bits(self.security, self.q)
        return [pow(self.g, self.r, self.p),
                (pow(self.g, m, self.p) * pow(self.h, self.r, self.p))
                % self.p]

    def verify(self, m, r, com):
        return (com[0] == pow(self.g, r, self.p)) and (com[1] == ((pow(self.g, m, self.p) * pow(self.h, self.r, self.p) % self.p)))

    def add(self, c1, c2):
        return (c1[0] * c2[0]) % self.p, (c1[1] * c2[1]) % self.p

    def multiply(self, c, a):
        return pow(c, a, self.p)


class Pedersen(Groups.PrimeOrder, Commitment):
    def __init__(self, security):
        super(Pedersen, self).__init__(security, True, 'Pedersen')

    def commit(self, m):
        self.m = m
        self.r = utils.random_bits(self.security, self.q)
        return (pow(self.g, m, self.p)) * (pow(self.h, self.r, self.p)) % self.p

    def verify(self, m, r, com):
        return com == ((pow(self.g, m, self.p)) * (pow(self.h, r, self.p)) % self.p)

    def add(self, c1, c2):
        return (c1 * c2) % self.p

    def multiply(self, c, a):
        return pow(c, a, self.p)
