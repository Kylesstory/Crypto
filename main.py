import os, json
from Encryption import Encryption 
from Signature import Signature

dictionary = {'Upper': ['Encryption', 'Signature'], 'lower': ['encryption', 'signature'], 'cipher': ['ciphertext', 'signatures'], 'en-cipher': ['Encrypt a message', 'Sign a message'], 'de-cipher': ['Decrypt a ciphertext', 'Verify a signature'], 'user': ['receiver', 'signer'], 'en-ciphered': ['encrypted', 'signed'], 'key': ['public', 'secret']}
parameters = None # the whole data for an algorithm, stored in files
security = 16 # secure parameter that should be about 1024; 16 is a computable but insecure choice.
index = -1 # 0 for encryption; and 1 for signature

def loadJsonFile(path, initData):
	if not (os.path.exists(path) or os.path.isfile(path)):
		saveJsonFile(path, initData)
		return True, initData # newly created; and data
	else: 
		with open(path, 'r') as f:
			data = json.load(f)
			f.close()
		return False, data

def saveJsonFile(path, data):
	with open(path, 'w') as f:
		json.dump(data, f)
		f.close()

def chooseFromList(_list, header, footer):
	n = -1
	length = len(_list)
	while not (n > -1 and n < length):
		print('\n\t-- %s --\n' % header)
		for i in range(length): print('[%d]\t%s' % (i + 1, _list[i]))
		n = int(input('\n%s ' % footer)) - 1
	print('\n\t-- %s --' % _list[n])
	return n

def listUsers():
	if len(parameters['names']):
		print('\nindex\tname\t%s\tpublic key\n' % dictionary['cipher'][index])
		count = 0
		for u in parameters['names']: 
			user = parameters['users'][parameters['names'][count]]
			print('[%d]\t%s\t\t%d\t%s' % (count + 1, parameters['names'][count], len(user[storage]), user['pk']))
			count += 1
	else: print('\nNo user exists. Please enter [3] to add a new user to the system.')

index = chooseFromList(['Public key encryption', 'Digital signature', 'Reset all data'], 'Cryptographic function list', 'Please choose your function.')
new, settings = loadJsonFile(os.getcwd() + '/settings.json', {'encryption': ['RSA', 'ElGamal', 'Paillier', 'CramerShoup'], 'signature':['RSA', 'DSA'], 'initData': {'RSA': {'names': [], 'users': {}, 'security': security}, 'ElGamal': {'q': 0, 'names': [], 'users': {}, 'security': security}, 'Paillier': {'names': [], 'users': {}, 'security': security}, 'CramerShoup': {'q': 0, 'names': [], 'users': {}, 'security': security}}})
if index == 2: # reset all stored data
	pathes = [os.getcwd() + '/%s/%s.json' % (dictionary['Upper'][x], y) for x in range(2) for y in settings[dictionary['lower'][x]]]
	pathes.append(os.getcwd() + '/settings.json')
	print('\n\t-- Json file list --\n')
	for p in pathes: 
		if os.path.exists(p): print(p)
	if 'y' == input('\nConfirm to delete all json and pycache files? [y/N] '):
		for p in pathes: 
			if os.path.exists(p): os.remove(p)
		caches = ['%s/%s/__pycache__/' % (os.getcwd(), d) for d in ['Encryption', 'Signature', 'Essential']]
		for c in caches:
			for pyc in os.listdir(c):
				os.remove(c + pyc)
			os.removedirs(c)
else: # encryption or signature
	storage = dictionary['cipher'][index]
	algoIndex = chooseFromList(settings[dictionary['lower'][index]], '%s algorithm list' % dictionary['Upper'][index], 'Please choose one %s algorithm.' % dictionary['lower'][index])
	path = os.getcwd() + '/%s/%s.json' % (dictionary['Upper'][index], settings[dictionary['lower'][index]][algoIndex])
	new, parameters = loadJsonFile(path, settings['initData'][settings[dictionary['lower'][index]][algoIndex]])
	algorithm = None
	if index: # Signature
		if algoIndex == 0: algorithm = Signature.RSA(parameters)
	else: #Encryption
		if algoIndex == 0: algorithm = Encryption.RSA(parameters)
		elif algoIndex == 1: algorithm = Encryption.ElGamal(parameters)
		elif algoIndex == 2: algorithm = Encryption.Paillier(parameters)
		elif algoIndex == 3: algorithm = Encryption.CramerShoup(parameters)
	if new: 
		parameters = algorithm.para
		saveJsonFile(path, parameters)
	print('\nParameters of the %s %s established.\n%s' % (settings[dictionary['lower'][index]][algoIndex], dictionary['lower'][index], algorithm.description))

	while True:
		command = chooseFromList(['Exit', 'List users', 'Add a new user', dictionary['en-cipher'][index], dictionary['de-cipher'][index]], 'Command list', 'Please enter a command.')
		if command == 0: break # break
		elif command == 1: # list users
			listUsers()
		elif command == 2: # add a new user
			name = input('\nPlease enter a name to create new public / private key pair. ')
			if name not in parameters['names']:
				sk, pk = algorithm.keyGenerate()
				parameters['names'].append(name)
				parameters['users'][name] = {'pk': pk, 'sk': sk, storage: []}
				saveJsonFile(path, parameters)
				print('%s\'s identity created.' % name)
				listUsers()
			else: print('\nUser %s exists.' % name)
		elif command in [3, 4]: 
			listUsers()
			if len(parameters['names']):
				n = chooseFromList(parameters['names'], 'User list', 'Please select the %s.' % dictionary['user'][index])
				user = parameters['users'][parameters['names'][n]]
				pk = user['pk']
				if command == 3: # en-cipher
					m = int(input('\nPlease enter the message desired to be %s (number from 0 to %d). ' % (dictionary['en-ciphered'][index], 2 ** security - 1)))
					if index: # signature
						sk = user['sk']
						cipher = algorithm.sign(sk, pk, m)
					else: cipher = algorithm.encrypt(pk, m) # encryption 
					user[storage].append([m, cipher] if index else cipher)
					saveJsonFile(path, parameters)
					print('\nMessage %s has been %s as %s using %s\'s %s key.' % (m, dictionary['en-ciphered'][index], cipher, parameters['names'][n], dictionary['key'][index]))
				else: # de-cipher
					if len(user[storage]):
						n = chooseFromList(user[storage], 'List of %s' % storage, 'Please choose one %s.' % storage)
						cipher = user[storage][n][1] if index else user[storage][n]
						if index: # verify a signature
							m = user[storage][n][0]
							print('\nSignature %d on message %d is verified %s.' % (cipher, m, 'valid' if algorithm.verify(pk, m, cipher) else 'invalid')) # verify a signature
						else: # decrypt a ciphertext
							sk = user['sk']
							m = algorithm.decrypt(sk, pk, cipher)
							print('\nThe decryption of ciphertext %s is %d.' % (cipher, m))
						if 'y' == input('Do you want to delete the %s %s? [y/N] ' % (storage, cipher) ):
							user[storage].pop(n)
							saveJsonFile(path, parameters)
							print('%s %s has been deleted.' % (dictionary['Upper'][index], cipher))
					else: print('\nNo %s exists.' % dictionary['cipher'][index])
				listUsers()
print('\n')
