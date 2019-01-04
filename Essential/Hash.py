import hashlib

def hash3_256(x, length):
	s = ''.join([str(i) for i in x])
	x = hashlib.sha3_256(s.encode('utf-8')).hexdigest()
	h = ''
	length = int(length / 4)
	while len(h) <= length: h = h + str(x)
	return int(h[:length], 16)