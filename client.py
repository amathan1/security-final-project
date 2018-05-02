import socket
import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class Client:

	def __init__(self, host_ip, port_no):
		'''Initialization parameters'''

		self.host_ip = host_ip;
		self.port_no = port_no;
		
		key = open("server_key.pem","r").read()
		# print ("Key:\n" + key)
		self.key = RSA.importKey(key)
		self.public_key = self.key.publickey()	# We use the public key of server for encryption
		key = open("client_key.pem", "r").read()
		self.key = RSA.importKey(key)	# Now we use this key for decryption



		# print ("Type of public_key is " + str(type(self.public_key)))
		# tmp = "This is fucked up man"
		# enc_shit = self.public_key.encrypt(tmp.encode("utf-8"), 32)
		# print ("The enc_data shit is " + str(enc_shit[0]))

		# dec_shit = self.key.decrypt(enc_shit)
		# print ("The dec_shit is " + dec_shit.decode("utf-8"))

		# key.close()



	def establish_connection(self):

		self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
		
		try:
			self.soc.connect((self.host_ip, self.port_no));

		except:
			print ("[Error] Connection could not be established")
			sys.exit();


	def vote(self):

		name = input("Enter your name: ")
		print ("Welcome, " + name + "\n")
		print ("\tMain Menu\n\nPlease enter a number(1-4)\n1. Vote\n2. My vote history\n3. Election result\n4. Quit\n")
		msg = input("Enter shit: ");

		while msg != ("quit" or "q"):

			# Encrypt the message using public key of the server.
			cipher = PKCS1_OAEP.new(self.public_key)
			enc_msg = cipher.encrypt(msg.encode("utf8"))

			self.soc.sendall(enc_msg)
			
			# response = self.soc.recv(1024)
			# cipher = PKCS1_OAEP.new(self.key)
			# response = cipher.decrypt(client_input)
			# response = client_input.decode("utf8").rstrip()

			msg = input(">>>: ");

		# Terminate the connection after one transfer
		self.soc.send(b'quit');




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