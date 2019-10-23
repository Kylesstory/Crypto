# -*- coding: utf-8 -*-
"""
.. module:: DigitalSignature
   :synopsis: The digital signature.
.. moduleauthor:: Kyle
"""

from Encryption.PKEncryption import RSA as PKE_RSA
from Essential import Groups, Utilities as utils
import abc


class DigitalSignature(object):
    """Digital Signatures"""

    def __init__(self, arg):
        """ The key (secret key / public key) generation algorithm. """
        raise NotImplementedError("DigitalSignature is abstract.")

    @abc.abstractmethod
    def sign(self, m):
        # The signer signs a message m using the secret key and
        # output a signature s.
        raise NotImplementedError(
            "The signing algorithm has not been implemented.")

    @abc.abstractmethod
    def verify(self, m, s):
        # The verifier inputs a message m and a signature s and
        # outputs whether the signature is valid or not using the
        # signer's public key.
        raise NotImplementedError(
            "The verification algorithm has not been implemented.")

    def demo(self, message):
        s = self.sign(message)
        self.params['message'] = message
        self.params['signature'] = s
        self.params['verification'] = self.verify(message, s)
        utils.show('%s signature' % self.name, self.params)


class RSA(Groups.RSA, DigitalSignature):
    def __init__(self, security):
        super(RSA, self).__init__(security)

    def sign(self, m):
        return pow(utils.hash(m, self.security, self.n), self.d, self.n)

    def verify(self, m, s):
        return pow(s, self.e, self.n) == utils.hash(m, self.security, self.n)


class DSA(Groups.PrimeOrder, DigitalSignature):
    def __init__(self, security):
        super(DSA, self).__init__(security, False, 'DSA')
        self.sk, self.pk = utils.dlPair(security, self.g, self.q, self.p)
        self.params['sk'] = self.sk
        self.params['pk'] = self.pk

    def sign(self, m):
        r = s = 0
        while r == s or s == 0:
            while r == s or r == 0:
                k = utils.randomBits(self.security, self.q)
                r = pow(self.g, k, self.p) % self.q
            s = utils.divide(utils.hash(m, self.security,
                                        self.q) + self.sk * r, k, self.q)
        return [r, s]

    def verify(self, m, sig):
        r = sig[0]
        s = sig[1]
        assert r > 0 and r < self.q and s > 0 and s < self.q
        w = utils.modinv(s, self.q)
        gk = ((pow(self.g, utils.hash(m, self.security, self.q) * w,
                   self.p) * pow(self.pk, r * w, self.p)) % self.p) % self.q
        return (r == gk)
