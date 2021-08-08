import requests
import time
import base64
import ecdsa

def wallet():
	response = None
	while response not in ["1","2","3","4"]:
		response = input(""" What do you want to do?
			1) Generate Waller
			2) Send Coins to another Wallet
			3) Check transactions
			4) Quit\n""")
	if response == "1":
		print("""===========IMPORTANT NOTICE: SAVE THIS CREADENTIALS OR YOU WONT BE ABLE TO RETRIEVE THIS INFORMATIUON EVER AGAIN\n""")
		generate_ECDSA_keys()
	elif response == "2":
		addr_from = input("Type / paste in your wallet address (public key)\n")
		private_key = input("Type / paste in your private key\n")
		addr_to = input("To: Destination wallet address?")
		amount = input("Amount: number of coins you want to transfer\n")
		print("=========================================\n\n")
		print("Is everything correct?\n")
		print("From: {0}\nPrivate Key: {1}\nTo: {2}\nAmount: {3}\n".format(addr_from, private_key, addr_to, amount))
		response = input("y/n:  ")
		if response.lower() == "y":
			send_transaction(addr_from, private_key, addr_to, amount)
	elif response == "3":
		check_transactions()
	else:
		quit()



def send_transaction(addr_from, private_key, addr_to, amount):

	if len(private_key) == 64:
		signature, message = sign_ECDSA_msg(private_key)
		url = 'https://localhost:5000/txion'
		payload = {"from":addr_from,
			"to":addr_to,
			"amount":amount,
			"signature": signature.decode(),
			"message":message}

		headers = {"Content-Type": "application/json"}

		res = requests.post(url, json=payload, headers = headers)
		print(res.text)
	else:
		print("Wrong address or key length, Verify and try again")

def check_transactions():
	# this retrives the entire blockchain
	# the speed depends upon the length of the blockchain

	try:
		res = requests.get('http://localhost:5000/blocks')
		print(res.text)
	except requests.ConnectionError:
		print("Connection error, make sure you are connected to the node")

def generate_ECDSA_keys():
	# this function generates private and public keys
	# using the python library called //ecdsa///

	sk = ecdsa.SigningKey.generate(curve = ecdsa.SECP256k1)
	private_key = sk.to_string().hex()
	vk = sk.get_verifying_key()
	public_key = vk.to_string().hex()

	#  to encode the public key with a base64 bit crptography to make it more shorter
	public_key = base64.b64encode(bytes.fromhex(public_key))

	filename = input("Choose a name for your address: ") + ".txt"
	with open(filename, "w") as f:
		f.write("Private address: {0}\nWallet address / Public Key: {1}\n".format(private_key, public_key.decode()))
	print("Your nre address and the private key are now in the file {0}".format(filename))


def sign_ECDSA_msg(private_key):
	# this functions returns two parameters called
	# 1)Signature: a base64 
	# 2) Message: str

	message = str(round(time.time()))
	bmessage = message.encode()
	sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
	signature = base64.b64encode(sk.sign(bmessage))

	return signature, message

if __name__  == '__main__':
	print("===================================================")
	print("""
		A INSECURE CRYPTO NODLE v1.0.0 - BLOCKCHAIN SYSTEM\n\n
		""")
	print("===================================================")
	wallet()
	input("Press 	ENTER   to exit.....")

