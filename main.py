from Encryption import PKEncryption as PKE
from Signature import DigitalSignature as DS
from Commitment import Commitment as Commit
from Essential import Utilities as utils

security = 48
pkes = [PKE.RSA(security), PKE.ElGamal(security), PKE.Paillier(security), PKE.CramerShoup(security)]
dss = [DS.RSA(security), DS.DSA(security)]
commits = [Commit.HashCommit(security << 1), Commit.ElGamal(security), Commit.Pederson(security)]

for algorithm in (pkes + dss + commits):
	algorithm.demo(utils.randomBits(security - 3))

# pai = PKE.Paillier(security)
# pai.demo(utils.randomBits(security - 3))