from Encryption import PKEncryption as PKE
from Signature import DigitalSignature as DS
from Commitment import Commitment as Commit
from Essential import Utilities as utils

security = 128
pkes = [PKE.RSA(security << 1), PKE.ElGamal(security), PKE.Paillier(security), PKE.CramerShoup(security)]
dss = [DS.RSA(security << 1), DS.DSA(security)]
commits = [Commit.HashCommit(security << 1), Commit.ElGamal(security), Commit.Pederson(security)]

for algorithm in (pkes + dss + commits):
	algorithm.demo(utils.randomBits(security - 3))
