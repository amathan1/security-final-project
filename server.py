import socket
import sys
import traceback
from threading import Thread
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA


class Server:

	def __init__(self, host_no, port_no, max_people=5):
		'''Initialize the host ip and port number'''

		self.host_no = host_no
		self.port_no = port_no
		
		# Parameters
		self.people_voted = 0
		self.max_people = max_people
		self.people = self.generate_map()
		self.state = 0

		# Socket
		self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		
		# Server cipher
		key = open("server_key.pem","rb").read()		
		self.key = RSA.importKey(key)
		self.server_cipher = PKCS1_OAEP.new(self.key)


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

		print ("We are inside the client")

		approved = self.authenticate(connection.recv(4096))

		if not approved:
			connection.sendall("0".encode("utf8"))
		else:
			connection.sendall("1".encode("utf8")) 

		is_active = True

		while is_active:

			try:
				client_input = self.process(connection.recv(4096))

			except:
				connection.close()
				break


			if client_input == "4":
				connection.close()
				print("Connection with " + ip + " : " + port + " is now closed")
				is_active = True

			else:
				print ("Processed result : {}".format(client_input))
				connection.sendall("-".encode("utf8"))

		return True


	def authenticate(self, __input):

		client_input = __input
		details, signature = client_input[:256], client_input[256:]
		decoded_input = self.server_cipher.decrypt(details)
		decoded_input = decoded_input.decode("utf8")
		name, v_number = decoded_input.split()
		try:
			assert(self.people[name] == v_number)
		except:
			return False

		key = RSA.importKey((open(name+".pem", "r")).read())
		key = key.publickey()
		_hash = SHA.new(name.encode("utf8"))
		verifier = PKCS1_v1_5.new(key)
		return verifier.verify(_hash, signature)



	def process(self, client_input):

		pass


	def generate_map(self):

		_file = open("voterinfo.txt", "r")
		_hist = open("history.txt", "r")
		v_info = dict()
		voted = dict()

		cur_str = _file.readlines().split()
		cur_hst = _file.readlines().split()

		for n, i in enumerate(cur_str[0]):
			v_info[i] = cur_str[1][n]
			voted[i] = cur_hst[1][n]


		# while (cur_str is not ""):
		# 	name, num = cur_str.split()
		# 	_, hist = cur_hst.split()
		# 	print ("We are now reading ", name)
		# 	v_info[name] = num
		# 	v_hist[name] = hist
		# 	cur_str = _file.readline()
		# 	cur_hst = _hist.readline()

		print("Total length : ", len(v_hist.keys()))

		for i in v_info.keys():
			print (i, v_info[i], v_hist[i])

		return v_info





def main():

	host_no = "127.0.0.1"
	port_no = 54321

	serv = Server(host_no, port_no)
	serv.establish_server()



if __name__ == "__main__":
    main()

