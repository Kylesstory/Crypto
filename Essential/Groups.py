# -*- coding: utf-8 -*-
"""
.. module:: Groups
   :synopsis: The cyclic groups.
.. moduleauthor:: Kyle
"""

from Essential import Utilities as utils


class CompositeOrder(object):
    """ Compose-order groups. """

    def __init__(self, security, name):
        self.security = security
        half = int(security / 2)
        p, p2 = utils.strong_prime(half)
        q = p
        while (q == p):
            q, q2 = utils.strong_prime(half)
        self.n = p * q
        self.p2q2 = p2 * q2
        self.params = {'security': security, 'n': self.n}
        self.name = name


class RSA(CompositeOrder):
    """ RSA groups. """

    def __init__(self, security):
        super(RSA, self).__init__(security, 'RSA')
        _lambda = self.p2q2 << 1
        self.params['e'] = self.e = utils.coprime(security, _lambda)
        self.params['d'] = self.d = utils.mod_inv(self.e, _lambda)


class PrimeOrder(object):
    """ Prime-order groups. """

    def __init__(self, security, moreGenerator, name):
        self.security = security
        self.p, self.q = utils.strong_prime(security)
        self.g = utils.coprime(security, self.p, self.q)
        self.params = {'security': security,
                       'p': self.p, 'q': self.q, 'g': self.g}
        self.name = name
        if moreGenerator:
            self.h = self.g
            while self.h == self.g:
                self.h = utils.coprime(security, self.p, self.q)
            self.params['h'] = self.h
