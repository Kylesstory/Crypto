from Encryption import PKEncryption as PKE
from Signature import DigitalSignature as DS

message = 79
pkes = [PKE.RSA(256), PKE.ElGamal(128), PKE.Paillier(128), PKE.CramerShoup(128)]
dss = [DS.RSA(256), DS.DSA(128)]

# for pke in pkes:
# 	pke.demo(message)

for ds in dss:
	ds.demo(message)
# pkes[2].demo(message)