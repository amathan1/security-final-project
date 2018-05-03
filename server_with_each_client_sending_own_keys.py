import socket
import sys
import traceback
from threading import Thread
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os


class Server:

	def __init__(self, host_no, port_no):
		'''Initialize the host ip and port number'''

		self.host_no = host_no
		self.port_no = port_no
		self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		os.system("rm *pem")
		os.system("openssl genpkey -algorithm RSA -out server_private_key.pem -pkeyopt rsa_keygen_bits:2048")
		os.system("openssl rsa -pubout -in server_private_key.pem -out server_public_key.pem")
		server_key = open("server_private_key.pem","r").read()
		self.server_private_key = RSA.importKey(server_key)	# Now we use this key for decryption
		self.private_cipher = PKCS1_OAEP.new(self.server_private_key)



	def establish_server(self):

		self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		print ("Server established")

		try:
			self.soc.bind((self.host_no, self.port_no))

		except:
			print ("[Error] Bind failed")
			sys.exit()

		self.soc.listen(5)
		print ("Socket waiting to accept connections")

		while True:

			connection, address = self.soc.accept()
			ip, port = str(address[0]), str(address[1])

			try:
				Thread(target=self.client_thread, args=(connection, ip, port)).start()

			except:
				print ("Not able to spawn a new thread")
				traceback.print_exc()

		self.soc.close()



	def client_thread(self, connection, ip, port, max_buffer_size = 4096):


		session_key = self.identify_client(connection.recv(max_buffer_size))
		connection.sendall("1".encode())

		client_input = connection.recv(max_buffer_size)
		self.finish_handshake(client_input, session_key)

		if (ds_verified):
			message = "1"
			connection.sendall(message)

		is_active = True

		while is_active:

			client_input = self.receive_input(connection, max_buffer_size)

			# split_string = 

			if client_input == "4":
				connection.close()
				print("Connection with " + ip + " : " + port + " is now closed")
				is_active = True

			else:
				print ("Processed result : {}".format(client_input))
				connection.sendall("-".encode("utf8"))



	def receive_input(self, connection, max_buffer_size):

		client_input = connection.recv(max_buffer_size)
		# cipher = PKCS1_OAEP.new(self.key)
		decoded_input = self.private_cipher.decrypt(client_input)
		decoded_input = decoded_input.decode("utf8").rstrip()  # decode and strip end of line

		return str(decoded_input)


	def process_input(self, input_str):

	    pass


	def identify_client(self, client_input):
		'''Create a client key object'''

		client_input = client_input.decode()
		return RSA.importKey(client_input)

	
	def finish_handshake(self, client_input, key):

		client_cipher = PKCS1_OAEP.new(key)
		decoded = client_input.decode().rstrip()
		_id, _ds = decoded.split(",,")
		_id = self.private_cipher.decrypt(_id)
		_id = _id.decode()

		
		_ds = self.public_key.decrypt(_ds)
		_name, _vnumber = _id.split(",")
		print ("Name is : " + _name + " and vnumber is " + _vnumber)








def main():

	host_no = "127.0.0.1"
	port_no = 54321

	serv = Server(host_no, port_no)
	serv.establish_server()



if __name__ == "__main__":
    main()

