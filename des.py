#! /usr/bin/env python

###################################################################################
#			The report for this assignment is in 'Report.pdf', in my SVN
#
#	Andrew Lutz
#	0664122
#	SFWR ENG 4C03 - Assignment 1
#	The following code is an implementation of the DES
#	encryption algorithm in ECB mode, written in python
#	des.py
#	February 1, 2011
#
###################################################################################
import sys

class des(object):
	
	bold = "\033[1m"		#This variable is used to bold outputted text
	reset = "\033[0;0m"		#This is used to stop bolding outputted text
	msg = [0]*64		#This global variable holds the user plaintext
	key = [0]*64		#This global variable holds the user security key
	IFLAG = False		#This bool is used for the -info input arguement, 
						#the user can enter this if they wish to view the 
						#operations at each stage of the algorithm
						
	#This method checks the input arguements and sets flag accordingly
	for arg in sys.argv:		
		if arg[:] == "-info":
			IFLAG = True

		
	#permutation table for initial permutation
	pc1 = [56, 48, 40, 32, 24, 16,  8,
			0, 57, 49, 41, 33, 25, 17,
		  	9,  1, 58, 50, 42, 34, 26,
		 	18, 10,  2, 59, 51, 43, 35,
		 	62, 54, 46, 38, 30, 22, 14,
		  	6, 61, 53, 45, 37, 29, 21,
			13,  5, 60, 52, 44, 36, 28,
			20, 12,  4, 27, 19, 11,  3
			]
			
	# number left rotations of pc1
	left_rotations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

	# permuted choice key (table 2)
	pc2 = [
		13, 16, 10, 23,  0,  4,
		 2, 27, 14,  5, 20,  9,
		22, 18, 11,  3, 25,  7,
		15,  6, 26, 19, 12,  1,
		40, 51, 30, 36, 46, 54,
		29, 39, 50, 44, 32, 47,
		43, 48, 38, 55, 33, 52,
		45, 41, 49, 35, 28, 31
	]

	# initial permutation IP
	ip = [57, 49, 41, 33, 25, 17, 9,  1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7,
		56, 48, 40, 32, 24, 16, 8,  0,
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6
	]

	# Expansion table for turning 32 bit blocks into 48 bits
	expansion_table = [
		31,  0,  1,  2,  3,  4,
		 3,  4,  5,  6,  7,  8,
		 7,  8,  9, 10, 11, 12,
		11, 12, 13, 14, 15, 16,
		15, 16, 17, 18, 19, 20,
		19, 20, 21, 22, 23, 24,
		23, 24, 25, 26, 27, 28,
		27, 28, 29, 30, 31,  0
	]

	# The (in)famous S-boxes
	sbox = [
		# S1
		[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		 [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		 [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		 [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		# S2
		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		 [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		 [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		 [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		# S3
		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		 [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		 [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		 [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		# S4
		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		 [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		 [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		 [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		# S5
		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		 [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		 [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		 [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		# S6
		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		 [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		 [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		 [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		# S7
		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		 [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		 [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		 [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		# S8
		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		 [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		 [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		 [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
	]


	# 32-bit permutation function P used on the output of the S-boxes
	p = [
		15, 6, 19, 20, 28, 11,
		27, 16, 0, 14, 22, 25,
		4, 17, 30, 9, 1, 7,
		23,13, 31, 26, 2, 8,
		18, 12, 29, 5, 21, 10,
		3, 24
	]

	# final permutation IP^-1
	fp = [
		39,  7, 47, 15, 55, 23, 63, 31,
		38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29,
		36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27,
		34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25,
		32,  0, 40,  8, 48, 16, 56, 24
	]
	
	
	###The following method gets input from the user and stores it
	def getInput(self):
		validInput = False
		while (validInput == False):
			msg = raw_input("Enter 64-bit string (plaintext):")
			if len(msg) != 8:	#Error checking to ensure the string is 64-bits
				print msg," is not a 64-bit string"	
				continue
			validInput = True	
			self.msg = self.String_to_BitList(msg)	#Transforms the input msg to bitlist and stores it
				
		validInput = False	
		while (validInput == False):	
			key = raw_input("Enter 64-bit string (key):")
			if len(key) != 8:	#Error checking to ensure the string is 64-bits
				print key," is not a 64-bit string"
				continue
			self.key = self.String_to_BitList(key)	#Transforms the input key to bitlist and stores it
			validInput = True
		
		#Output more information is IFLAG is set
		if self.IFLAG == True:
			print self.bold,"\nThe 64-bit plaintext you entered is...",self.reset
			print self.String_to_BitList(msg)
			print self.bold,"\nThe 64-bit key you entered is...",self.reset
			print self.String_to_BitList(key),"\n"	


	#This method transforms an ascii input into a list of bits, having a bitlist
	#allows for easy bit manipulation
	def String_to_BitList(self,data):
		data = [ord(c) for c in data]
		l = len(data) * 8
		result = [0] * l
		pos = 0
		for ch in data:
			i = 7
			while i >= 0:
				if ch & (1 << i) != 0:	#this bitwise ANDS the data with powers of 2 to get individual bits are 0 or 1
					result[pos] = 1
				else:
					result[pos] = 0
				pos += 1
				i -= 1			
		return result


	#Remove_ParityBits
    #The following function was used until I
    #realized the permutation tables automatically
    #removes the parity bits	
	def Remove_Parity_Bits(self,data):
		l = len(data) / 8
		i = 1
		for ch in data:
			while i <= l:
				del data[i*7:(i*7)+1]
	  			i += 1
		print l
		print data	
	
		
	#This method is used to permutate bit lists with permutation tables above
	def permutate(self,table, block):
		"""Permutate this block with the specified table"""
		return list(map(lambda x: block[x], table))
		
		
	#This method takes the permutation of initial keys and generates the
	#16 subkeys that will be used in the 16 rounds in the next stage	
	def make_sub_keys(self, key,rotations):
		C = key[:28]	#Initial split of permuted key into C and D
		D = key[28:]
		Kn = [ [0] * 48 ] * 16	# 16 48-bit keys (K1 - K16)
		
		#Output more information is IFLAG is set
		if self.IFLAG == True:
			print self.bold,"\nThis is the result of splitting the first permutation into two 32-bit blocks...\n",self.reset
			print "C[0] is ..."
			print C,"\n"
			print "D[0] is ..."
			print D,"\n"
			
		#Output more information is IFLAG is set
		if self.IFLAG == True:
			print self.bold,"\nThese are the 16 subkeys...\n",self.reset	
		i = 0
		while i < 16:
			j = 0
			#Perform left circular shits
			while j < self.left_rotations[i]:
				C.append(C[0])	#Adds the first element in the list to the end of the list
				del C[0]	#Deletes first element in the list

				D.append(D[0])	#Adds the first element in the list to the end of the list
				del D[0]	#Deletes first element in the list

				j += 1

			# Create one of the 16 subkeys through pc2 permutation
			temp = C+D	#temporarily stores the concatenation of lists C and D
			#The following line permutates C+D and saves it as a subkey
			Kn[i] = self.permutate(self.pc2, temp)
			#Kn[i] = list(map(lambda x: temp[x], self.pc2))
			#Output more information is IFLAG is set
			if self.IFLAG == True:
				print "This is subkey K[",self.bold,i+1,self.reset,"]"
				print Kn[i], "\n"	
			i += 1
		return Kn	#returns list of 16 subkeys, Kn is a list of lists
		
	
	def data_proc(self,data,keys):
		IP = list(map(lambda x: data[x], self.ip))	#First permutation of plaintext
		L = IP[:32]
		R = IP[32:]
		Rexp = [0]*48	#This holds the expansion table permutation
		ExK = [0]*48	#This holds the value of XOR'ing the subkey and the expanded permutation
		P = [0]*32	#This holds the final permutation of the f function.
		#Output more information is IFLAG is set
		if self.IFLAG == True:
			print "\nL[0] is..."
			print L,"\n"
			print "R[0] is..."
			print R,"\n"
		
		i = 0
		while i < 16:	#Loops for the 16 rounds of encryption
			#Output more information is IFLAG is set
			if self.IFLAG == True:
				print self.bold,"Round ",i+1, self.reset	
			Rexp = list(map(lambda x: R[x], self.expansion_table))	#Permutation of R[]
			#Output more information is IFLAG is set
			if self.IFLAG == True:
				print self.bold,"E  :",self.reset,Rexp
				print "Key  :", keys[i]
			j = 0
			while j < 48:
				ExK[j] = (keys[i][j]^Rexp[j])	#XOR's the key and permutated R[]
				j += 1
			#Output more information is IFLAG is set
			if self.IFLAG == True:	
				print self.bold,"E xor Key  :", self.reset, ExK
			i += 1
			B = [ExK[:6], ExK[6:12], ExK[12:18], ExK[18:24], ExK[24:30], ExK[30:36], ExK[36:42], ExK[42:]]
			#Output more information is IFLAG is set
			if self.IFLAG == True:
				print self.bold,"B boxes,  :",self.reset, B
			
			Bnew = [0] * 32
			k = 0
			pos = 0
			while k < 8:	#This loop determines the int value of the row and column values needed to access the Sbox's
				m = (B[k][0] << 1) + B[k][5]	#Uses bit shifting and manipulation to find value
				n = (B[k][1] << 3) + (B[k][2] << 2) + (B[k][3] << 1) + B[k][4]
				value = self.sbox[k][m][n]	#Stores the sbox value
				
				#The following four lines transform the sbox value into a 4-bit string
				Bnew[pos] = (value & 8) >> 3	
				Bnew[pos + 1] = (value & 4) >> 2
				Bnew[pos + 2] = (value & 2) >> 1
				Bnew[pos + 3] = (value & 1)
				pos +=4			
				k += 1
			if self.IFLAG == True:
				print self.bold,"Sbox  :",self.reset,Bnew
			P = list(map(lambda x: Bnew[x], self.p))
			if self.IFLAG == True:
				print self.bold,"P  :", self.reset,P
			l = 0
			Rtemp = [0] * 32 #temporary R[] value to hold the XOR result
			while l < 32:
				Rtemp[l] = (L[l]^P[l])
				l += 1
			L = R
			R = Rtemp
			if self.IFLAG == True:
				print self.bold,"L[i]  :",self.reset,L
				print self.bold,"R[i]  :",self.reset,R,"\n\n"
			
		RL = R+L
		if self.IFLAG == True:
			print self.bold,"RL[]  :\n",self.reset,RL
		output = list(map(lambda x: RL[x], self.fp))
		if self.IFLAG == True:
			print self.bold,"Output  :\n",self.reset,output
		return output;
	
	
	#This method transforms the 64-bit string to hex characters for easier reading
	def bit_to_hex(self,data):
		bstr = ''
		i = 0
		while i < 64:
			j = 0
			while j < 8:
				bstr += str(data[i])
				j += 1
				i += 1		
		nstr = "0x%x" % int(bstr,2)

		k = 2
		hex_str = ""
		while k < 18:
			hex_str += nstr[k:k+2]
			hex_str += " "
			k += 2
		print self.bold,"\nYour ciphertext in hex is...\n","\t\t\t\t",hex_str,"\n\n",self.reset
				
des = des()	#create instance of class des()
des.getInput()
data4 = des.permutate(des.pc1, des.key)
if des.IFLAG == True:
	print des.bold,"\nResult of first permutation of key...",des.reset
	print data4
print
keys = des.make_sub_keys(data4, des.left_rotations)
out_bits = des.data_proc(des.msg,keys)
des.bit_to_hex(out_bits)
