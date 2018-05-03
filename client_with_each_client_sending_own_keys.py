import socket
import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256



class Client:

	def __init__(self, host_ip, port_no):
		'''Initialization parameters'''

		self.host_ip = host_ip;
		self.port_no = port_no;
		
		key = open("server_key.pem","r").read()
		self.key = RSA.importKey(key)
		self.public_key = self.key.publickey()	# We use the public key of server for encryption
		key = open("client_key.pem", "r").read()
		self.key = RSA.generate(2048)	# Now we use this key for decryption
		self.own_key = self.key.publickey()
		self.own_key = self.own_key.exportKey()
		self.name = ""
		self.cipher = PKCS1_OAEP.new(self.public_key)
		# print ("The type of cipher is " + str(type(self.public_key)))


	def establish_connection(self):

		self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
		
		try:
			self.soc.connect((self.host_ip, self.port_no));

		except:
			print ("[Error] Connection could not be established")
			sys.exit();



	def vote(self):

		# Get input from user and send the encrypted version to the server

		self.soc.sendall(self.own_key)
		initial = input("Enter your name and voter number seperated by space>> ")
		to_send = self.prepare_handshake(initial)
		self.soc.sendall(to_send)

		# Verify if the server has approved the request.
		response = self.soc.recv(4096)
		response = self.cipher.decrypt(response)
		response = response.decode("utf8")

		if (response == "0"):
			print ("Invalid name or registration number")
			return 1


		print ("Welcome, " + self.name + "\n")
		print ("\tMain Menu\n\nPlease enter a number(1-4)\n1. Vote\n2. My vote history\n3. Election result\n4. Quit\n")
		msg = input("Enter shit: ");

		while msg != ("quit" or "q"):

			# Encrypt the message using public key of the server.
			enc_msg = self.cipher.encrypt(msg.encode("utf8"))

			self.soc.sendall(enc_msg)
			
			# response = self.soc.recv(1024)
			# cipher = PKCS1_OAEP.new(self.key)
			# response = cipher.decrypt(client_input)
			# response = client_input.decode("utf8").rstrip()

			msg = input(">>>: ");

		# Terminate the connection after one transfer
		self.soc.send(b'quit');



	def prepare_handshake(self, initial_string):
		'''Prepare the initial handshake that concatenates name, number
		   and sends it encrypted with digital signature to the server.'''


		# Concatenate name and v_number with public key of server.
		self.name, v_number = initial_string.split()
		hs_string = self.name + "|" + v_number
		enc_hs_string = self.cipher.encrypt(hs_string.encode("utf8"))

		# Hash name and digitally sign it using private key.
		hasher = SHA256.new()
		hasher.update(self.name.encode("utf8"))
		hashed_name = hasher.hexdigest()
		p_cipher = PKCS1_OAEP.new(self.key)
		ds_hash = p_cipher.encrypt(hashed_name.encode("utf8"))

		# Finally, concatenate name, v_number and digital signature
		to_send = str(enc_hs_string) + "||" + str(ds_hash)
		to_send = to_send.encode("utf8")

		for_now = to_send.decode("utf8")
		_id, _ds = for_now.split("||")

		print ("Id is " + _id + " and DS is " + _ds)
		dec_id = PKCS1_OAEP.new(self.key.publickey).decrypt(_id)

		return to_send



def main():

	host = "127.0.0.1"
	port = 54321

	print ("Host:%s Port:%d" %(host, port))
	cli = Client(host, port)

	cli.establish_connection()

	exit_code = 1

	while (exit_code != 0):
		cli.vote()



if __name__ == "__main__":
	main()




'''
vname = input("Enter name: ")
    #soc.sendall(vname.encode("utf8"))

    #Accept reg num and send to server:
    vregnum = input("Enter registration number: ")
    #soc.sendall(vregnum.encode("utf8"))
    vinfo = vname + vregnum
    vinfo_encoded = str.encode(vinfo)
    enc_cipher = PKCS1_OAEP.new(public_key)
    enc_info = enc_cipher.encrypt(vinfo_encoded)

    print("Encrypted data: {}".format(enc_info))

    dec_cipher = PKCS1_OAEP.new(private_key)
    dec_info_encoded = dec_cipher.decrypt(enc_info)
    dec_info = dec_info_encoded.decode()
    print("Decrypted data: {}".format(dec_info))

'''