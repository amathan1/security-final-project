import socket
import sys
import traceback
from threading import Thread
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class Server:

	def __init__(self, host_no, port_no):
		'''Initialize the host ip and port number'''

		self.host_no = host_no
		self.port_no = port_no
		self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		key = open("client_key.pem", "r").read()
		self.key = RSA.importKey(key)
		self.public_key = self.key.publickey()	# We use the public key of server for encryption
		key = open("server_key.pem","r").read()		
		self.key = RSA.importKey(key)	# Now we use this key for decryption
		threads = list()	# Used for joining threads in the end


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


	def client_thread(self, connection, ip, port, max_buffer_size = 1024):

		is_active = True

		while is_active:

			client_input = self.receive_input(connection, max_buffer_size)

			if client_input == "4":
				connection.close()
				print("Connection with " + ip + " : " + port + " is now closed")
				is_active = True

			else:
				print ("Processed result : {}".format(client_input))
				connection.sendall("-".encode("utf8"))



	def receive_input(self, connection, max_buffer_size):

		client_input = connection.recv(max_buffer_size)
		cipher = PKCS1_OAEP.new(self.key)
		decoded_input = cipher.decrypt(client_input)
		decoded_input = decoded_input.decode("utf8").rstrip()  # decode and strip end of line

		return str(decoded_input)


	def process_input(self, input_str):

	    


	    return 






def main():

	host_no = "127.0.0.1"
	port_no = 54321

	serv = Server(host_no, port_no)
	serv.establish_server()



if __name__ == "__main__":
    main()

