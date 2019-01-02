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
		print('\nindex\tname\tpublic key\tcipher number\n')
		count = 0
		for u in parameters['names']: 
			print('[%d]\t%s\t%d\t\t%d' % (count + 1, parameters['names'][count], parameters['users'][parameters['names'][count]]['pk'], len(parameters['users'][parameters['names'][count]]['cipher'])))
			count += 1
	else: print('\nNo user exists. Please enter [3] to add a new user to the system.')

category = 0 # encryption = 0, signature = 1
new, settings = loadJsonFile(os.getcwd() + '/settings.json', {'encryption': ['ElGamal'], 'signature':[], 'initData': {'ElGamal': {'q': 0, 'names': [], 'users': {}, 'security': 16}}})
algoIndex = chooseFromList(settings['encryption'], 'Encryption algorithm list', 'Please choose one encrytpion algorithm.')
path = os.getcwd() + '/%s/%s.json' % ('Signature' if category else 'Encryption', settings['encryption'][algoIndex])
new, parameters = loadJsonFile(path, settings['initData'][settings['encryption'][algoIndex]])
algorithm = None
if category: # Signature
	pass
else: #Encryption
	if algoIndex == 0: algorithm = Encryption.ElGamal(parameters)
if new: 
	parameters = algorithm.para
	saveJsonFile(path, parameters)
print('\nParameters of the %s %s established.\n%s' % (settings['encryption'][algoIndex], 'signature' if category else 'encryption', algorithm.description))

while True:
	if category == 0: # encryption
		command = chooseFromList(['Exit', 'List users', 'Add a new user', 'Encrypt a messge', 'Decrypt a cipher'], 'Command list', 'Please enter a command.')
		if command == 0: break
		elif command == 1:
			listUsers()
		elif command == 2: 
			name = input('\nPlease enter a name to create new public / private key pair. ')
			sk, pk = algorithm.keyGenerate()
			parameters['names'].append(name)
			parameters['users'][name] = {'pk': pk, 'sk': sk, 'cipher': []}
			saveJsonFile(path, parameters)
			print('%s\'s identity created.' % name)
			listUsers()
		elif command == 3:
			listUsers()
			index = chooseFromList(parameters['names'], 'User list', 'Please select the receiver.')
			receiver = parameters['users'][parameters['names'][index]]
			pk = receiver['pk']
			m = int(input('\nPlease enter the plaintext desired to be encrypted. '))
			c = algorithm.encrypt(pk, m)
			receiver['cipher'].append(c)
			saveJsonFile(path, parameters)
			print('\nMessage %s has been encrypted using public key %d.' % (m, pk))
			listUsers()
		elif command == 4: 
			listUsers()
			index = chooseFromList(parameters['names'], 'User list', 'Please select the receiver.')
			receiver = parameters['users'][parameters['names'][index]]
			sk = receiver['sk']
			index = chooseFromList(receiver['cipher'], 'Cipher list', 'Please choose one cipher to decrypt.')
			c = receiver['cipher'][index]
			m = algorithm.decrypt(sk, c)
			print('\nThe decryption of ciphertext %s is %d.' % (c, m))
			if 'y' == input('Do you want to delete the decrypted ciphertext %s? (y/n) [n] ' % (c) ):
				receiver['cipher'].pop(index)
				saveJsonFile(path, parameters)
				print('Ciphertext %s has been deleted.' % (c))
			listUsers()
	else: # signature
		pass
print('\n')
