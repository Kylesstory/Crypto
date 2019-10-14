from Encryption import PKEncryption as PKE
from Signature import DigitalSignature as DS
from Commitment import Commitment as Commit

message = 75
pkes = [PKE.RSA(256), PKE.ElGamal(128), PKE.Paillier(128), PKE.CramerShoup(128)]
dss = [DS.RSA(256), DS.DSA(128)]
commits = [Commit.HashCommit(256), Commit.ElGamal(128), Commit.Pederson(128)]

for pke in pkes:
	pke.demo(message)

for ds in dss:
	ds.demo(message)

for commit in commits:
	commit.demo(message)