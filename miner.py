import time
import hashlib
import json
import requests
import base64
from flask import Flask, request
from multiprocessing import Process, Pipe
import ecdsa


from miner_config import  MINER_ADDRESS, MINER_NODE_URL, PEER_NODES

node = Flask(__name__)

class Block:
	def __init__(self, index, timestamp, data, previous_hash):


		self.index = index,
		self.timestamp  = timestamp,
		self.data = data,
		self.previous_hash = previous_hash,
		self.hash = self.hash_block()

	def hash_block(self):
		'''
		Creates a new hashusing sha'''
		sha = hashlib.sha256()
		sha.update((str(self.index) + str(self.data) + str(self.previous_hash)).encode('utf-8'))
		return sha.hexdigest()

	def create_genesis_block():
		'''
		this function is used to create a genesis block
		A genesis block is the first block on the block(chain)
		As it has no previous blocks to be hashed with,
		it created a manual index zero as previous hash.

		'''

		return Block(0, time.time(), {
			"proof-of-work": 9,
			"transactions": None},
			"0")

BLOCKCHAIN = [create_genesis_block()]

NODE_PENDING_TRANSACTION = []

def proof_of_work(last_proof, blockchain):
	incrementer = last_proof + 1
	start_time = time.time()
	while not (incrementer % 7919 == 0 and incrementer % last_proof == 0):
		incrementer += 1
		if int((time.time_() - start_time) % 60) == 0:
			new_blockchain = concensus(blockchain)
			if new_blockchain:
				return False, new_blockchain
		return incrementer, blockchain

def mine(a, blockchain, node_pending_transactions):
    BLOCKCHAIN = blockchain
    NODE_PENDING_TRANSACTIONS = node_pending_transactions
    while True:
        last_block = BLOCKCHAIN[-1]
        last_proof = last_block.data['proof-of-work']
        proof = proof_of_work(last_proof, BLOCKCHAIN)
        if not proof[0]:
            BLOCKCHAIN = proof[1]
            a.send(BLOCKCHAIN)
            continue
        else:
            NODE_PENDING_TRANSACTIONS = requests.get(url = MINER_NODE_URL + '/txion', params = {'update':MINER_ADDRESS}).content
            NODE_PENDING_TRANSACTIONS = json.loads(NODE_PENDING_TRANSACTIONS)
            NODE_PENDING_TRANSACTIONS.append({
                "from": "network",
                "to": MINER_ADDRESS,
                "amount": 1})
            new_block_data = {
                "proof-of-work": proof[0],
                "transactions": list(NODE_PENDING_TRANSACTIONS)
            }
            new_block_index = last_block.index + 1
            new_block_timestamp = time.time()
            last_block_hash = last_block.hash
            NODE_PENDING_TRANSACTIONS = []
            mined_block = Block(new_block_index, new_block_timestamp, new_block_data, last_block_hash)
            BLOCKCHAIN.append(mined_block)
              "index": new_block_index,
              "timestamp": str(new_block_timestamp),
              "data": new_block_data,
              "hash": last_block_hash
            }, sort_keys=True) + "\n")
            a.send(BLOCKCHAIN)
            requests.get(url = MINER_NODE_URL + '/blocks', params = {'update':MINER_ADDRESS})

def find_new_chains():
    other_chains = []
    for node_url in PEER_NODES:
        block = requests.get(url = node_url + "/blocks").content
        block = json.loads(block)
        validated = validate_blockchain(block)
        if validated:
            # Add it to our list
            other_chains.append(block)
    return other_chains


def consensus(blockchain):
    other_chains = find_new_chains()
    BLOCKCHAIN = blockchain
    longest_chain = BLOCKCHAIN
    for chain in other_chains:
        if len(longest_chain) < len(chain):
            longest_chain = chain
    if longest_chain == BLOCKCHAIN:
        return False
    else:
        BLOCKCHAIN = longest_chain
        return BLOCKCHAIN


def validate_blockchain(block):

    return True


@node.route('/blocks', methods=['GET'])
def get_blocks():
    if request.args.get("update") == MINER_ADDRESS:
        global BLOCKCHAIN
        BLOCKCHAIN = b.recv()
    chain_to_send = BLOCKCHAIN
    chain_to_send_json = []
    for block in chain_to_send:
        block = {
            "index": str(block.index),
            "timestamp": str(block.timestamp),
            "data": str(block.data),
            "hash": block.hash
        }
        chain_to_send_json.append(block)

    chain_to_send = json.dumps(chain_to_send_json, sort_keys=True)
    return chain_to_send


@node.route('/txion', methods=['GET', 'POST'])
def transaction():
   
    if request.method == 'POST':
        new_txion = request.get_json()
        if validate_signature(new_txion['from'], new_txion['signature'], new_txion['message']):
            NODE_PENDING_TRANSACTIONS.append(new_txion)
            print("New transaction")
            print("FROM: {0}".format(new_txion['from']))
            print("TO: {0}".format(new_txion['to']))
            print("AMOUNT: {0}\n".format(new_txion['amount']))
            # Then we let the client know it worked out
            return "Transaction submission successful\n"
        else:
            return "Transaction submission failed. Wrong signature\n"
    elif request.method == 'GET' and request.args.get("update") == MINER_ADDRESS:
        pending = json.dumps(NODE_PENDING_TRANSACTIONS, sort_keys=True)
        # Empty transaction list
        NODE_PENDING_TRANSACTIONS[:] = []
        return pending


def validate_signature(public_key, signature, message):

    public_key = (base64.b64decode(public_key)).hex()
    signature = base64.b64decode(signature)
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
    try:
        return vk.verify(signature, message.encode())
    except:
        return False


def welcome_msg():
    print("""       =========================================\n
        SIMPLE COIN v1.0.0 - BLOCKCHAIN SYSTEM\n
       =========================================\n\n
        You can find more help at: https://github.com/cosme12/SimpleCoin\n
        Make sure you are using the latest version or you may end in
        a parallel chain.\n\n\n""")


if __name__ == '__main__':
    welcome_msg()
    # Start mining
    a, b = Pipe()
    p1 = Process(target=mine, args=(a, BLOCKCHAIN, NODE_PENDING_TRANSACTIONS))
    p1.start()
    # Start server to receive transactions
    p2 = Process(target=node.run(), args=b)
    p2.start()

