import ecdsa
import base64	



def main():

	

	sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
	print("This is the curve: " + str(Curve))
	print("this is sk: " + str(sk))
	pk1 = sk.to_string()
	print("this is sk to string: " + str(pk1))
	pk2 = sk.to_string().hex()
	print("this is sk to string and to hex: " + str(pk2))
	vk = sk.get_verifying_key()
	print("this is the verification key for sk: " + str(vk))
	pubkey = vk.to_string().hex()
	print("this is public key into string into hex: "  + str(pubkey))
	pubkey = base64.b64encode(bytes.fromhex(pubkey))
	print("This is public key with base64 encoding: " + str(pubkey))




if __name__ == '__main__':
	main()