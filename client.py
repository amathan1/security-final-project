import socket
import sys, os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from random import randint
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA


class Client:

	def __init__(self, host_ip, port_no):
		'''Initialization parameters'''

		self.host_ip = host_ip;
		self.port_no = port_no;

		self.name = ""
		self.random_number = randint(1, 999999)
		self.state = 0

		server_key = open("server_key.pem","r").read()
		server_key_opened = RSA.importKey(server_key)
		server_public_key = server_key_opened.publickey()	# We use the public key of server for encryption
		self.server_cipher = PKCS1_OAEP.new(server_public_key)
		self.client_cipher = self.generate_new_key()



	def establish_connection(self):

		self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
		
		try:
			self.soc.connect((self.host_ip, self.port_no));

		except:
			print ("[Error] Connection could not be established")
			sys.exit();


	def vote(self):

		details = input("Enter your name and voter_id number seperated by space >> ")
		first_cipher_text = self.process_details(details)
		self.soc.sendall(first_cipher_text)

		if self.soc.recv(1024).decode("utf8") == "0":
			print ("Invalid name or number")
			self.soc.close()
			return True


		print ("Welcome, " + self.name + "\n")
		print ("\tMain Menu\n\nPlease enter a number(1-4)\n1. Vote\n2. My vote history\n3. Election result\n4. Quit\n")
		msg = input(">>> ");

		while msg != ("quit" or "q"):

			enc_msg = self.server_cipher.encrypt(msg.encode("utf8"))
			self.soc.sendall(enc_msg)
			self.state += int(msg)
			from_server = self.soc.recv(1024)
			self.process_input(from_server)
			msg = input("Enter: ");

		# Terminate the connection after one transfer
		self.soc.send(b'quit');


	def process_details(self, details):

		enc_details = self.server_cipher.encrypt(details.encode("utf8"))
		self.name = details.split()[0]
		os.system("cp %d.pem %s.pem" %(self.random_number, self.name))
		os.system("rm %d.pem" %self.random_number)
		key = RSA.importKey(open(self.name+".pem").read())
		_hash = SHA.new(self.name.encode("utf8"))
		signer = PKCS1_v1_5.new(key)
		signature = signer.sign(_hash)
		print ("The length of the details is " + str(len(enc_details)) + " and length of signature is " + str(len(signature)))
		final_message = enc_details + signature
		return final_message


	def generate_new_key(self):

		new_client_key = RSA.generate(2048)
		new_file = open(str(self.random_number)+".pem", "wb")
		new_file.write(new_client_key.exportKey("PEM"))
		new_file.close()
		return PKCS1_OAEP.new(new_client_key)


	def process_input(self, msg):

		pass




def main():

	host = "127.0.0.1"
	port = 54321

	print ("Host:%s Port:%d" %(host, port))
	cli = Client(host, port)

	cli.establish_connection()
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