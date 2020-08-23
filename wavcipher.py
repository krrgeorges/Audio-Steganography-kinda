data = ""

from Crypto.Cipher import AES
from Crypto.Cipher import Salsa20
from Crypto.Cipher import ChaCha20
import random
from scipy.io import wavfile
import numpy as np

# Padding and Encryption

ENCRYPTION_SUITE = {"AES|EAX":1,"SALSA20":2,"CHACHA20":3}

ENCRYPTION_TYPE = 3

MIN_LEN = 130000
MAX_LEN = 260000







padding_start_flag = "|_=||=_|"

data += padding_start_flag

if len(data)%16 != 0:
	print("Padding to the multiple of 16...")
	satisfied = False
	padding_length = 0
	i = 1
	while satisfied == False:
		padding = 16*i
		if padding > len(data):
			satisfied = True
			padding_length = padding
			break
		i+=1
	bytes_to_pad = padding_length - len(data)
	for j in range(0,bytes_to_pad):
		data+="_"

print("Constructing ciphertext...")


key_length = 0
nonce_length = 0

if ENCRYPTION_TYPE == 1:
	key_length = 16
	nonce_length = 16
elif ENCRYPTION_TYPE == 2:
	key_length = 32
	nonce_length = 8
elif ENCRYPTION_TYPE == 3:
	key_length = 32
	nonce_length = 12



chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_+-+[]"
key = ''.join([chars[random.randrange(0,len(chars))] for i in range(key_length)]).encode("utf8")
nonce = ''.join([chars[random.randrange(0,len(chars))] for i in range(nonce_length)]).encode("utf8")

if ENCRYPTION_TYPE == 1:
	cipher = AES.new(key, AES.MODE_EAX,nonce)
	ciphertext = cipher.encrypt(data.encode("utf8"))
elif ENCRYPTION_TYPE == 2:
	cipher = Salsa20.new(key=key,nonce=nonce)
	ciphertext = cipher.encrypt(data.encode("utf8"))
elif ENCRYPTION_TYPE == 3:
	cipher = ChaCha20.new(key=key,nonce=nonce)
	ciphertext = cipher.encrypt(data.encode("utf8"))


print("Constructing Empty Forma...")

f_l = random.randrange(MIN_LEN,MAX_LEN)
forma = []
for i in range(f_l):
	forma.append([0,0])
	print("Status :",str(round((i/f_l)*100,1))+"%",end="\r")

# constructing first symbol list

print("Constructing Symbol List...")

c_chars = []

for x in ciphertext:
	if bytes([x]) not in c_chars:
		c_chars.append(bytes([x]))

symbol_list = {}

alpha_list = []

for c in c_chars:
	if c not in symbol_list:
		unique = False;
		alpha,delta = 0,0
		while unique != True:
			alpha = random.randrange(-30000,30000)
			delta = random.randrange(0,f_l//(len(ciphertext)+30))
			found = False
			for symbol in symbol_list:
				if symbol_list[symbol][0] == alpha and symbol_list[symbol][1] == delta:
					found = True
					break
			if found ==  False:
				unique = True
		symbol_list[c] = [alpha,delta]


# filling forma

print("Filling up the empty forma...")

initial_delta = random.randrange(0,30000)

forma[0] = [initial_delta,initial_delta]

present_index = 0


for i in range(0,initial_delta):
	alpha = random.randrange(-30000,30000)
	present_index = present_index+1
	try:
		forma[present_index] = [alpha,alpha]
	except:
		forma.append([alpha,alpha])
		fl = len(forma)

mutation = False

for c in ciphertext:
	c_data = symbol_list[bytes([c])]
	c_alpha = c_data[0]
	c_delta = c_data[1]
	present_index = present_index+1
	try:
		forma[present_index] = [c_alpha,c_alpha]
		alpha_list.append(c_alpha)
	except IndexError:
		forma.append([c_alpha,c_alpha])
		alpha_list.append(c_alpha)
		f_l = len(forma)
		if mutation == False:
			mutation = True
	for i in range(0,c_delta):
		present_index = present_index+1
		alpha = random.randrange(-30000,30000)
		try:
			forma[present_index] = [alpha,alpha]
			alpha_list.append(alpha)
		except IndexError:
			forma.append([alpha,alpha])
			alpha_list.append(alpha)
			f_l = len(forma)
			if mutation == False:
				mutation = True


# plot forma alpha

# plt.plot(alpha_list)
# plt.show()

# DECIDE flags

print("Deciding Key Flags..")

unique = False;
alpha,delta = 0,0
while unique != True:
	alpha = random.randrange(-30000,30000)
	delta = random.randrange(0,f_l//(len(ciphertext)+30))
	found = False
	for symbol in symbol_list:
		if symbol_list[symbol][0] == alpha and symbol_list[symbol][1] == delta:
			found = True
			break
	if found ==  False:
		unique = True
symbol_list["FLAG_START"] = [alpha,delta]

unique = False;
alpha,delta = 0,0
while unique != True:
	alpha = random.randrange(-30000,30000)
	delta = random.randrange(0,f_l//(len(ciphertext)+30))
	found = False
	for symbol in symbol_list:
		if symbol_list[symbol][0] == alpha and symbol_list[symbol][1] == delta:
			found = True
			break
	if found ==  False:
		unique = True
symbol_list["FLAG_END"] = [alpha,delta]


#DECIDE metadata : key

print("Constructing key deciders...")

c_chars = []

for x in key:
	if bytes([x]) not in c_chars:
		c_chars.append(bytes([x]))

for c in c_chars:
	if c not in symbol_list:
		unique = False;
		alpha,delta = 0,0
		while unique != True:
			alpha = random.randrange(-30000,30000)
			delta = random.randrange(0,f_l//(len(ciphertext)+30))
			found = False
			for symbol in symbol_list:
				if symbol_list[symbol][0] == alpha and symbol_list[symbol][1] == delta:
					found = True
					break
			if found ==  False:
				unique = True
		symbol_list[c] = [alpha,delta]


# adding flag_start

print("Adding FLAG_START...")

flag_start_delta = symbol_list["FLAG_START"][1]
flag_start_alpha = symbol_list["FLAG_START"][0]

present_index = present_index+1
try:
	forma[present_index] = [flag_start_alpha,flag_start_alpha]
except IndexError:
	forma.append([flag_start_alpha,flag_start_alpha])
	f_l = len(forma)


for i in range(0,flag_start_delta):
	alpha = random.randrange(-30000,30000)
	present_index = present_index+1
	try:
		forma[present_index] = [alpha,alpha]
	except IndexError:
		forma.append([alpha,alpha])
		f_l = len(forma)
	

# adding key

print("Adding key...")

for c in key:
	c_data = symbol_list[bytes([c])]
	c_alpha = c_data[0]
	c_delta = c_data[1]
	present_index = present_index+1
	try:
		forma[present_index] = [c_alpha,c_alpha]
		alpha_list.append(c_alpha)
	except IndexError:
		forma.append([c_alpha,c_alpha])
		alpha_list.append(c_alpha)
		f_l = len(forma)
	for i in range(0,c_delta):
		present_index = present_index+1
		alpha = random.randrange(-30000,30000)
		try:
			forma[present_index] = [alpha,alpha]
			alpha_list.append(alpha)
		except IndexError:
			forma.append([alpha,alpha])
			alpha_list.append(alpha)
			f_l = len(forma)


# adding flag_end

print("Adding FLAG_END...")

flag_end_delta = symbol_list["FLAG_END"][1]
flag_end_alpha = symbol_list["FLAG_END"][0]

present_index = present_index+1
try:
	forma[present_index] = [flag_end_alpha,flag_end_alpha]
except IndexError:
	forma.append([flag_end_alpha,flag_end_alpha])
	f_l = len(forma)


for i in range(0,flag_end_delta):
	alpha = random.randrange(-30000,30000)
	present_index = present_index+1
	try:
		forma[present_index] = [alpha,alpha]
	except IndexError:
		forma.append([alpha,alpha])
		f_l = len(forma)



# DECIDE nonce flags

print("Deciding Nonce Flags...")


unique = False;
alpha,delta = 0,0
while unique != True:
	alpha = random.randrange(-30000,30000)
	delta = random.randrange(0,f_l//(len(ciphertext)+30))
	found = False
	for symbol in symbol_list:
		if symbol_list[symbol][0] == alpha and symbol_list[symbol][1] == delta:
			found = True
			break
	if found ==  False:
		unique = True
symbol_list["NONCE_FLAG_START"] = [alpha,delta]

unique = False;
alpha,delta = 0,0
while unique != True:
	alpha = random.randrange(-30000,30000)
	delta = random.randrange(0,f_l//(len(ciphertext)+30))
	found = False
	for symbol in symbol_list:
		if symbol_list[symbol][0] == alpha and symbol_list[symbol][1] == delta:
			found = True
			break
	if found ==  False:
		unique = True
symbol_list["NONCE_FLAG_END"] = [alpha,delta]


#DECIDE metadata : nonce

print("Constructing Nonce deciders...")

c_chars = []


for x in nonce:
	if bytes([x]) not in c_chars:
		c_chars.append(bytes([x]))

for c in c_chars:
	if c not in symbol_list:
		unique = False;
		alpha,delta = 0,0
		while unique != True:
			alpha = random.randrange(-30000,30000)
			delta = random.randrange(0,f_l//(len(ciphertext)+30))
			found = False
			for symbol in symbol_list:
				if symbol_list[symbol][0] == alpha and symbol_list[symbol][1] == delta:
					found = True
					break
			if found ==  False:
				unique = True
		symbol_list[c] = [alpha,delta]


# adding nonce_flag_start

print("Adding NONCE_FLAG_START...")

flag_start_delta = symbol_list["NONCE_FLAG_START"][1]
flag_start_alpha = symbol_list["NONCE_FLAG_START"][0]

present_index = present_index+1
try:
	forma[present_index] = [flag_start_alpha,flag_start_alpha]
except IndexError:
	forma.append([flag_start_alpha,flag_start_alpha])
	f_l = len(forma)



for i in range(0,flag_start_delta):
	alpha = random.randrange(-30000,30000)
	present_index = present_index+1
	try:
		forma[present_index] = [alpha,alpha]
	except IndexError:
		forma.append([alpha,alpha])
		f_l = len(forma)
	

# adding nonce

print("Adding Nonce..")

for c in nonce:
	c_data = symbol_list[bytes([c])]
	c_alpha = c_data[0]
	c_delta = c_data[1]
	present_index = present_index+1
	try:
		forma[present_index] = [c_alpha,c_alpha]
		alpha_list.append(c_alpha)
	except IndexError:
		forma.append([c_alpha,c_alpha])
		alpha_list.append(c_alpha)
		f_l = len(forma)
	for i in range(0,c_delta):
		present_index = present_index+1
		alpha = random.randrange(-30000,30000)
		try:
			forma[present_index] = [alpha,alpha]
			alpha_list.append(alpha)
		except IndexError:
			forma.append([alpha,alpha])
			alpha_list.append(alpha)
			f_l = len(forma)


# adding nonce_flag_end

print("Adding NONCE_FLAG_END...")

flag_end_delta = symbol_list["NONCE_FLAG_END"][1]
flag_end_alpha = symbol_list["NONCE_FLAG_END"][0]

present_index = present_index+1
try:
	forma[present_index] = [flag_end_alpha,flag_end_alpha]
except IndexError:
	forma.append([flag_end_alpha,flag_end_alpha])
	f_l = len(forma)


for i in range(0,flag_end_delta):
	alpha = random.randrange(-30000,30000)
	present_index = present_index+1
	try:
		forma[present_index] = [alpha,alpha]
	except IndexError:
		forma.append([alpha,alpha])
		f_l = len(forma)

# adding encryption type

if ENCRYPTION_TYPE not in symbol_list:
	unique = False;
	alpha,delta = 0,0
	while unique != True:
		alpha = random.randrange(-30000,30000)
		delta = random.randrange(0,f_l//(len(ciphertext)+30))
		found = False
		for symbol in symbol_list:
			if symbol_list[symbol][0] == alpha and symbol_list[symbol][1] == delta:
				found = True
				break
		if found ==  False:
			unique = True
	symbol_list[ENCRYPTION_TYPE] = [alpha,delta] 

present_index = present_index+1
try:
	forma[present_index] = [symbol_list[ENCRYPTION_TYPE][0],symbol_list[ENCRYPTION_TYPE][0]]
except IndexError:
	forma.append([symbol_list[ENCRYPTION_TYPE][0],symbol_list[ENCRYPTION_TYPE][0]])
for i in range(0,symbol_list[ENCRYPTION_TYPE][1]):
	alpha = random.randrange(-30000,30000)
	present_index = present_index+1
	try:
		forma[present_index] = [alpha,alpha]
	except IndexError:
		forma.append([alpha,alpha])
		f_l = len(forma)




# final_format : initial_delta_number+inital_delta+(c_alpha+c_delta)*+flag_start_alpha+flag_start_delta_+key_alpha+key_delta)*+flag_end_alpha+flag_end_delta+nonce_flag_start_alpha+nonce_flag_start_delta+(nonce_alpha+nonce_delta)*+nonce_flag_end_alpha+nonce_flag_end_delta+enc_tye


# to_add : type of cipher, ciphersuite

print("Writing .wav file...")
wavfile.write("test.wav",rate=42100,data=np.asarray(forma))























print("Reading .wav file...")

fs,tforma = wavfile.read("test.wav")

print("Extracting metadata and ciphertext...")

ciphertext = b""
key = b""
nonce = b""

t_ciphertext = []
t_key = []
t_nonce = []

def get_symbol_from_alpha(symbol_list,alpha):
	for s in symbol_list:
		if symbol_list[s][0] == alpha:
			return s

initial_delta = tforma[0][0]
present_index = 0

present_index = present_index+initial_delta

print("Extracting ciphertext...")

is_flag_found = False

alpha,delta,s = 0,0,""


while is_flag_found == False:
	present_index = present_index+1
	alpha = tforma[present_index][0]
	s = get_symbol_from_alpha(symbol_list,alpha)
	delta = symbol_list[s][1]
	present_index = present_index+delta
	if str(s) == "FLAG_START":
		is_flag_found = True
		break
	ciphertext += s


print("Extracting key...")

is_flag_stop_found = False



while is_flag_stop_found == False:
	present_index = present_index+1
	alpha = tforma[present_index][0]
	s = get_symbol_from_alpha(symbol_list,alpha)
	delta = symbol_list[s][1]
	present_index = present_index+delta
	if str(s) == "FLAG_END":
		is_flag_stop_found = True
		break
	key += s

print("Extracting nonce...")

present_index = present_index+1

alpha = tforma[present_index][0]
s = get_symbol_from_alpha(symbol_list,alpha)
delta = symbol_list[s][1]
if s=="NONCE_FLAG_START":
	for i in range(0,delta):
		present_index = present_index+1
	is_nflag_stop_found = False
	while is_nflag_stop_found == False:
		present_index = present_index+1
		alpha = tforma[present_index][0]
		s = get_symbol_from_alpha(symbol_list,alpha)
		delta = symbol_list[s][1]
		present_index = present_index+delta
		if s == "NONCE_FLAG_END":
			is_nflag_stop_found = True
			break
		nonce += s

present_index = present_index+1
alpha = tforma[present_index][0]
DECRYPTION_TYPE = get_symbol_from_alpha(symbol_list,alpha)

plaintext = ""

if DECRYPTION_TYPE == 1:
	cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
	plaintext = cipher.decrypt(ciphertext).decode("utf8")
elif DECRYPTION_TYPE == 2:
	cipher = Salsa20.new(key=key, nonce=nonce)
	plaintext = cipher.decrypt(ciphertext).decode("utf8")
elif DECRYPTION_TYPE == 3:
	cipher = ChaCha20.new(key=key, nonce=nonce)
	plaintext = cipher.decrypt(ciphertext).decode("utf8")

plaintext = plaintext[0:plaintext.index(padding_start_flag)]

print("Extracted plaintext : ",plaintext.encode("utf8"))

















































































