# Generate keys for the server and client


from Crypto.PublicKey import RSA

# Generate key pair for the server.
serv_key = RSA.generate(2048)
f_serv = open("server_key.pem", "w")
f_serv.write(serv_key.exportKey("PEM"))
f_serv.close()

# Generate key pair for client (Depricated)
# cli_key = RSA.generate(2048)
# f_cli = open("client_key.pem", "w")
# f_cli.write(cli_key.exportKey("PEM"))
# f_cli.close()


vinfo = open("voterinfo.txt", "w")
vhist = open("history.txt", "w")
vinfo.write("Arvind 1994\n")
vhist.write("Arvind 0\n")
vinfo.write("Noob 1995\n")
vhist.write("Noob 0\n")
vinfo.write("Trump 1996\n")
vhist.write("Trump 0\n")
vinfo.write("Bobby 1997\n")
vhist.write("Bobby 0\n")
vinfo.close()
vhist.close()


# Various states
# 0. Main Menu
# 1. Voting Menu
# 2. Voting History Menu
# 3.Election Result
