from Encryption import PKEncryption as PKE
from Signature import DigitalSignature as DS
from Commitment import Commitment as Commit
from ZeroKnowledgeProof import ZKP
from Essential import Utilities as utils

security = 128
trust = 8
# pkes = [PKE.RSA(security), PKE.ElGamal(security), PKE.Paillier(security), PKE.CramerShoup(security)]
# dss = [DS.RSA(security), DS.DSA(security)]
# commits = [Commit.HashCommit(security << 1), Commit.ElGamal(security), Commit.Pedersen(security)]
zkps = [ZKP.SingleValue(security, trust)]

# for algorithm in (pkes + dss + commits):
# 	algorithm.demo(utils.randomBits(security - 3))

for zkp in zkps:
	zkp.demo(utils.randomBits(security - 3))
