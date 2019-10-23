from Encryption import PKEncryption as PKE
from Signature import DigitalSignature as DS
from Commitment import Commitment as Commit
from ZeroKnowledgeProof import ZKP, NIZK
from Essential import Utilities as utils

security = 128
confidence = 8

pkes = [PKE.RSA(security), PKE.ElGamal(security),
        PKE.Paillier(security), PKE.CramerShoup(security)]
dss = [DS.RSA(security), DS.DSA(security)]
commits = [Commit.HashCommit(security << 1), Commit.RSA(
    security), Commit.ElGamal(security), Commit.Pedersen(security)]
zkps = [ZKP.Schnorr(security, confidence),
        ZKP.GuillouQuisquater(security, confidence),
        ZKP.FiatShamir(security, confidence),
        ZKP.ChaumPedersen(security, confidence)]
nizks = [NIZK.Schnorr(security), NIZK.GuillouQuisquater(
    security), NIZK.ChaumPedersen(security)]

for algorithm in (pkes + dss + commits + zkps + nizks):
    message = utils.randomBits(security - 2)
    algorithm.demo(message)
