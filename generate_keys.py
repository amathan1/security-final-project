# Generate keys for the server and client


from Crypto.PublicKey import RSA


serv_key = RSA.generate(2048)
cli_key = RSA.generate(2048)

f_serv = open("server_key.pem", "wb")
f_cli = open("client_key.pem", "wb")

f_serv.write(serv_key.exportKey("PEM"))
f_cli.write(cli_key.exportKey("PEM"))

f_serv.close()
f_cli.close()
