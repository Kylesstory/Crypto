import os, json
from Encryption import Encryption

parameters = None
security = 16 # secure parameter that should be about 1024; 16 is a computable but insecure choice.
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
	index = -1
	length = len(_list)
	while not (index > -1 and index < length):
		print('\n\t-- %s --\n' % header)
		for i in range(length): print('[%d]\t%s' % (i + 1, _list[i]))
		index = int(input('\n%s ' % footer)) - 1
	print('\n\t-- %s --' % _list[index])
	return index

def listUsers():
	if len(parameters['names']):
		print('\nindex\tname\tcipher number\tpublic key\n')
		count = 0
		for u in parameters['names']: 
			print('[%d]\t%s\t\t%d\t%s' % (count + 1, parameters['names'][count], len(parameters['users'][parameters['names'][count]]['cipher']), parameters['users'][parameters['names'][count]]['pk']))
			count += 1
	else: print('\nNo user exists. Please enter [3] to add a new user to the system.')

category = ['Encryption', 'encryption', 'Signature', 'signature']
typeIndex = 0 # 0 for encryption, 1 for signature
_type = category[2 * typeIndex + 1]
Type = category[2 * typeIndex ]
new, settings = loadJsonFile(os.getcwd() + '/settings.json', {'encryption': ['RSA', 'ElGamal', 'Paillier', 'CramerShoup'], 'signature':[], 'initData': {'RSA': {'names': [], 'users': {}, 'security': security}, 'ElGamal': {'q': 0, 'names': [], 'users': {}, 'security': security}, 'Paillier': {'names': [], 'users': {}, 'security': security}, 'CramerShoup': {'q': 0, 'names': [], 'users': {}, 'security': security}}})
algoIndex = chooseFromList(settings[_type], '%s algorithm list' % Type, 'Please choose one %s algorithm.' % _type)
path = os.getcwd() + '/%s/%s.json' % (Type, settings[_type][algoIndex])
new, parameters = loadJsonFile(path, settings['initData'][settings[_type][algoIndex]])
algorithm = None
if typeIndex: # Signature
	pass
else: #Encryption
	if algoIndex == 0: algorithm = Encryption.RSA(parameters)
	elif algoIndex == 1: algorithm = Encryption.ElGamal(parameters)
	elif algoIndex == 2: algorithm = Encryption.Paillier(parameters)
	elif algoIndex == 3: algorithm = Encryption.CramerShoup(parameters)
if new: 
	parameters = algorithm.para
	saveJsonFile(path, parameters)
print('\nParameters of the %s %s established.\n%s' % (settings[_type][algoIndex], _type, algorithm.description))

while True:
	if typeIndex == 0: # encryption
		command = chooseFromList(['Exit', 'List users', 'Add a new user', 'Encrypt a messge', 'Decrypt a cipher'], 'Command list', 'Please enter a command.')
		if command == 0: break # break
		elif command == 1: # list users
			listUsers()
		elif command == 2: # add a new user
			name = input('\nPlease enter a name to create new public / private key pair. ')
			if name not in parameters['names']:
				sk, pk = algorithm.keyGenerate()
				parameters['names'].append(name)
				parameters['users'][name] = {'pk': pk, 'sk': sk, 'cipher': []}
				saveJsonFile(path, parameters)
				print('%s\'s identity created.' % name)
				listUsers()
			else: print('\nUser %s exists.' % name)
		elif command == 3: # encrypt
			listUsers()
			index = chooseFromList(parameters['names'], 'User list', 'Please select the receiver.')
			receiver = parameters['users'][parameters['names'][index]]
			pk = receiver['pk']
			m = int(input('\nPlease enter the plaintext desired to be encrypted (number from 0 to %d). ' % (2 ** security - 1)))
			c = algorithm.encrypt(pk, m)
			receiver['cipher'].append(c)
			saveJsonFile(path, parameters)
			print('\nMessage %s has been encrypted as %s using %s\'s public key %s.' % (m, c, parameters['names'][index], pk))
			listUsers()
		elif command == 4: #decrypt
			listUsers()
			index = chooseFromList(parameters['names'], 'User list', 'Please select the receiver.')
			receiver = parameters['users'][parameters['names'][index]]
			sk = receiver['sk']
			pk = receiver['pk']
			index = chooseFromList(receiver['cipher'], 'Cipher list', 'Please choose one cipher to decrypt.')
			c = receiver['cipher'][index]
			m = algorithm.decrypt(sk, pk, c)
			print('\nThe decryption of ciphertext %s is %d.' % (c, m))
			if 'y' == input('Do you want to delete the decrypted ciphertext %s? (y/n) [n] ' % (c) ):
				receiver['cipher'].pop(index)
				saveJsonFile(path, parameters)
				print('Ciphertext %s has been deleted.' % (c))
			listUsers()
	else: # signature
		pass
print('\n')
