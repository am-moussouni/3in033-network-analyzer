import contextlib
import codecs
import sys

""" Correspondance entre la valeur hexa d'un type Ethernet et de son utilisation """
types_ethernet = {
	"0800" : "IP Datagram",
	"0805" : "X.25 level 3",
	"0806" : "ARP",
	"8035" : "RARP",
	"8098" : "AppleTalk"
}

protocoles_ip = {
	"1" : "ICMP",
	"2" : "IGMP",
	"6" : "TCP",
	"8" : "EGP",
	"9" : "IGP",
	"17" : "UDP",
	"36" : "XTP",
	"46" : "RSVP"
}

types_options = {
	"0" : "EOOL",
	"1" : "NOP",
	"7" : "RR",
	"68" : "TS",
	"131" : "LSR",
	"137" : "SSR"
}

dhcp_opcode = {
	"01" : "Boot Request",
	"02" : "Boot Reply"
}

types_options_dhcp = {
	"1" : "Subnet mask",
	"3" : "Router",
	"6" : "Domain name server",
	"12" : "Host name",
	"15" : "Domain name",
	"31" : "Perform router discover",
	"33" : "Static route",
	"43" : "Vendor-specific information",
	"44" : "NetBIOS over TCP/IP name server",
	"46" : "NetBIOS over TCP/IP node type",
	"47" : "NetBIOS over TCP/IP scope",
	"50" : "Requested IP address",
	"51" : "IP address lease time",
	"54" : "DHCP server identifier",
	"55" : "Parameter request list",
	"53" : "DHCP message type",
	"58" : "Renewal time value",
	"59" : "Rebinding time value",
	"60" : "Vendor class identfier",
	"61" : "Client identifier",
	"81" : "Client fully qualified domain name",
	"116" : "DHCP auto-configuration",
	"249" : "Reserved for private use",
	"255" : "End"
}

dhcp_message_types = {
	"01" : "Discover",
	"02" : "Offer",
	"03" : "Request",
	"04" : "Decline",
	"05" : "Acknowledge",
	"06" : "Not Acknowledge",
	"07" : "Release",
	"08" : "Inform",
}

dns_types = {
	"0001" : "A",
	"0002" : "NS",
	"0005" : "CNAME",
	"000f" : "MX",
	"001c" : "AAAA"
}

def decodable_offset(offset):
	if len(offset) < 2 or not offset.isalnum():
		return False
	for chiffre_hex in offset:
		if chiffre_hex.isalpha():
			if not(chiffre_hex.lower() >= "a" and chiffre_hex.lower() <= "f"):
				return False
	return True
	
def decodable_byte(byte):
	if len(byte) != 2 or not byte.isalnum():
		return False
	for chiffre_hex in byte:
		if chiffre_hex.isalpha():
			if not(chiffre_hex.lower() >= "a" and chiffre_hex.lower() <= "f"):
				return False
	return True

""" Entrées :	- Le chemin vers le fichier contenant la trace brute
	Sorties :	- Une liste contenant tous les octets de la trace """
	
"""On lit le fichier ligne par ligne, puis on split chaque ligne en une liste d'octets.
Dans chaque ligne, le 1er élément est soit un offset, soit du texte parasite, et on les supprime dans les deux cas de liste (pop(0)). Ensuite, on supprime le texte parasite à la fin de la ligne s'il y en a (inutile si la ligne ne contient que du texte parasite et pas d'offset/hex, d'où le try/except)
"""
def lire_trace(path_to_file):
	with open(path_to_file, "rt") as f:
		frame_list = []
		line_list = f.read().splitlines()
		if int(line_list[0].split()[0], 16) != 0:
			print("Error: Malformed frame: Frame doesn't start with offset 0")
			quit()
		i = -1
		for j in range(len(line_list)):
			line_list[j] = line_list[j].split()
			if decodable_offset(line_list[j][0]):
				if int(line_list[j][0], 16) == 0:
					i = i+1
					frame_list.append([])
			frame_list[i].append(line_list[j])
			
		for frame in frame_list:
			for line in frame:
				if not decodable_offset(line[0]):
					frame.remove(line)
					
		#v2
		for frame in frame_list:
			last_offset = -1
			for idx, line in enumerate(frame):
				if idx != len(frame)-1:
					#print(str(int(line[0], 16)) + ">" + str(last_offset))
					if int(line[0], 16) > last_offset:
						next_offset = frame[(idx + 1) % len(frame)][0]
						#print(next_offset)
						last_offset = int(line[0], 16)
						if int(next_offset, 16) > 0:
							if ((len(line) - 1) == int(next_offset, 16) - int(line[0], 16)):
								line.pop(0)
							elif ((len(line) - 1) < int(next_offset, 16) - int(line[0], 16)):
								print("Error: Malformed frame: Line incomplete")
								quit()
							elif ((len(line) - 1) > int(next_offset, 16) - int(line[0], 16)):
								len_line = len(line) -1
								nb_bytes =  int(next_offset, 16) - int(line[0], 16)
								line.pop(0)
								del line [nb_bytes:]
				else:
					line.pop(0)
					for i in range(len(line)):
						if not decodable_byte(line[i]):
							del line[i:]
							break
							
				#print(line)
								
							
		
		
		#print(frame_list)
		return frame_list

""" Entrées :	- Un nombre en héxadécimal
	Sorties :	- Le même nombre convertit en binaire """
def hexa_en_binaire(suite_chiffres_h):
	nb_bits = len(suite_chiffres_h) * 4
	suite_chiffres_d = int(suite_chiffres_h, 16)
	suite_chiffres_b = bin(suite_chiffres_d)
	return suite_chiffres_b[2:].zfill(nb_bits) #pour supprimer le 0b + padding avec des 0

def binaire_en_hexa(suite_chiffres_b):
	suite_chiffres_d = int(suite_chiffres_b, 2)
	suite_chiffres_h = hex(suite_chiffres_d)
	return suite_chiffres_h

""" Entrées :	- Une liste contenant les octets de la trace
				- Le numéro du 1er octet (commence à 0) à retourner
				- Le nombre d'octets à retourner
	Sorties :	- Une liste contenant les octets voulus """
def obtenir_octets(liste_octets, octet_debut, nb_octets):
	liste_octets_voulus = []
	for i in range(octet_debut, octet_debut + nb_octets):
		liste_octets_voulus.append(liste_octets[i])
	return liste_octets_voulus
	
def liste_chiffres(liste_octets):
	liste_chiffres = []
	for i in range(len(liste_octets)):
		liste_chiffres.append(liste_octets[i][0])
		liste_chiffres.append(liste_octets[i][1])
	return liste_chiffres
	
def obtenir_chiffres(liste_chiffres, chiffre_debut, nb_chiffres):
	liste_chiffres_voulus = []
	for i in range(chiffre_debut, chiffre_debut+nb_chiffres):
		liste_chiffres_voulus.append(liste_chiffres[i])
	return liste_chiffres_voulus

""" Entrées :	- La liste d'octets formant l'entête Ethernet
	Sorties :	- (Affichage) Liste des différents champs de l'entête Ethernet et leurs valeurs """
def decodage_entete_ethernet(entete_ethernet):
	print("‣ Ethernet II")
	entete_ethernet_2 = obtenir_chiffres(liste_chiffres(entete_ethernet), 0, 28)
	adresse_dest = ""
	for i in range(0, 11, 2):
		adresse_dest = adresse_dest + ":" + entete_ethernet_2[i] + entete_ethernet_2[i+1]
	adresse_dest = adresse_dest.lstrip(":")
	print("\t‣ Destination address: " + adresse_dest)
	
	adresse_src = ""
	for i in range(12, 23, 2):
		adresse_src = adresse_src + ":" + entete_ethernet_2[i] + entete_ethernet_2[i+1] 
	adresse_src = adresse_src.lstrip(":")
	print("\t‣ Source address: " + adresse_src)
	
	type = entete_ethernet_2[24] + entete_ethernet_2[25] + entete_ethernet_2[26] + entete_ethernet_2[27]
	print("\t‣ Type: " + types_ethernet[type] + " (0x" + type + ")")
	
def decodage_entete_ip(liste_octets):
	print("‣ Internet Protocol Version 4 (IPv4)")
	entete_ip = obtenir_octets(liste_octets, 14, 20)
	entete_ip_2 = obtenir_chiffres(liste_chiffres(entete_ip), 0, 40)
	version = entete_ip_2[0]
	print("\t‣ Version: " + version)
	
	ihl = entete_ip_2[1]
	print("\t‣ IHL: " + str(4*int(ihl, 16)) + " octets (0x" + ihl + ")")

	tos = entete_ip_2[2] + "" + entete_ip_2[3]
	print("\t‣ Type of service: 0x" + tos)
	
	total_length = entete_ip_2[4] + "" + entete_ip_2[5] + "" + entete_ip_2[6] + "" + entete_ip_2[7]
	print("\t‣ Total length: " + str(int(total_length, 16)))
	
	ident = entete_ip_2[8] + "" + entete_ip_2[9] + "" + entete_ip_2[10] + "" + entete_ip_2[11]
	print("\t‣ Identification: 0x" + ident + " (" + str(int(ident, 16)) + ")")
	
	f_fo = entete_ip_2[12] + "" + entete_ip_2[13] + "" + entete_ip_2[14] + "" + entete_ip_2[15]
	f_fo = hexa_en_binaire(f_fo)
	print("\t‣ Flags:")
	print("\t\t‣ Reserved bit: 0")
	print("\t\t‣ Don't fragment: " + f_fo[1])
	print("\t\t‣ More fragment: " + f_fo[2])
	f_fo = f_fo[2:15]
	print("\t‣ Fragment offset: " + binaire_en_hexa(f_fo) + " (" + str(int(f_fo, 2)) + ")")
	
	ttl = entete_ip_2[16] + "" + entete_ip_2[17]
	print("\t‣ TTL: " + str(int(ttl, 16)))
	
	protocole = entete_ip_2[18] + "" + entete_ip_2[19]
	print("\t‣ Protocol: " + protocoles_ip[str(int(protocole, 16))] + " (" + str(int(protocole, 16)) + ")")
	
	checksum = entete_ip_2[20] + "" + entete_ip_2[21] + "" + entete_ip_2[22] + "" + entete_ip_2[23]
	print("\t‣ Header checksum: 0x" + checksum)
	
	adresse_src = ""
	for i in range(24, 31, 2):
		adresse_src = adresse_src + "." + str(int(str(entete_ip_2[i]) + str(entete_ip_2[i+1]), 16))
	adresse_src = adresse_src.lstrip(".")
	print("\t‣ Source address: " + adresse_src)
	
	adresse_dest = ""
	for i in range(32, 39, 2):
		adresse_dest = adresse_dest + "." + str(int(str(entete_ip_2[i]) + str(entete_ip_2[i+1]), 16))
	adresse_dest = adresse_dest.lstrip(".")
	print("\t‣ Destination address: " + adresse_dest)
	
	if 4*int(ihl, 16)!=20:
		trame = liste_chiffres(liste_octets)
		reste_trame = trame[68:]
		t1 = reste_trame[0] + "" + reste_trame[1]
		print("\t‣ Option: " + types_options[str(int(t1, 16))])
		while(int(t1, 16) != 0):
			if (t1 != '00' and t1 != '01'):
				l1 = reste_trame[2] + "" + reste_trame[3]
				print("\t\t‣ Length: " + str(int(l1, 16)) + " bytes")
				longeur_val = int(l1, 16) - 2
				val = ""
				for i in range(4, 4+longeur_val*2 - 1, 2):
					val = val + "" + reste_trame[i] + reste_trame[i+1]
				print("\t‣ Value: " + val)
				del reste_trame [:4+longeur_val*2]
			t1 = reste_trame[0] + "" + reste_trame[1]
			print("\t‣ Option: " + types_options[str(int(t1, 16))])
		for ind in (i for i,e in enumerate(trame) if e==reste_trame[0]):
			if trame[ind:ind+len(reste_trame)]==reste_trame:
				return ind+len(reste_trame)-1
	return 67
	
def find_sublist(sl,l):
    sll=len(sl)
    for ind in (i for i,e in enumerate(l) if e==sl[0]):
        if l[ind:ind+sll]==sl:
            return ind

#retourne la longeur de la partie data qu'elle encapsule
def decodage_entete_udp(entete_udp):
	print("‣ User Datagram Protocol (UDP)")
	src_port = entete_udp[0] + "" + entete_udp[1] + "" + entete_udp[2] + "" + entete_udp[3]
	print("\t‣ Source port: " + str(int(src_port, 16)))
	
	dest_port = entete_udp[4] + "" + entete_udp[5] + "" + entete_udp[6] + "" + entete_udp[7]
	print("\t‣ Destination port: " + str(int(dest_port, 16)))
	
	length = entete_udp[8] + "" + entete_udp[9] + "" + entete_udp[10] + "" + entete_udp[11]
	print("\t‣ Length: " + str(int(length, 16)))
	
	checksum = entete_udp[12] + "" + entete_udp[13] + "" + entete_udp[14] + "" + entete_udp[15]
	print("\t‣ Checksum: 0x" + checksum)
	return (int(length, 16)-8, int(src_port, 16))
	
def is_data_label(chiffre_hex):
	if chiffre_hex.lower() in ['c', 'd', 'e', 'f']:
		return False
	return True
	
def decodage_msg_dns(msg_dns):
	print("‣ Domain Name System (DNS)")
	ident = msg_dns[0] + "" + msg_dns[1] + "" + msg_dns[2] + "" + msg_dns[3]
	print("\t‣ Identifier: 0x" + ident)
	
	flags = msg_dns[4] + "" + msg_dns[5] + "" + msg_dns[6] + "" + msg_dns[7]
	print("\t‣ Flags: 0x" + flags)
	
	nb_quest = msg_dns[8] + "" + msg_dns[9] + "" + msg_dns[10] + "" + msg_dns[11]
	print("\t‣ Number of questions: " + str(int(nb_quest, 16)))
	
	nb_ans = msg_dns[12] + "" + msg_dns[13] + "" + msg_dns[14] + "" + msg_dns[15]
	print("\t‣ Number of answer RRs: " + str(int(nb_ans, 16)))
	
	nb_auth = msg_dns[16] + "" + msg_dns[17] + "" + msg_dns[18] + "" + msg_dns[19]
	print("\t‣ Number of authority RRs: " + str(int(nb_auth, 16)))
	
	nb_add = msg_dns[20] + "" + msg_dns[21] + "" + msg_dns[22] + "" + msg_dns[23]
	print("\t‣ Number of additional RRs: " + str(int(nb_add, 16)))
	
	dico = {}
	
	reste_msg = msg_dns[24:]
	if int(nb_quest, 16) != 0:
		print("\t‣ Queries")
	for i in range(int(nb_quest, 16)):
		pos = find_sublist(reste_msg, msg_dns)
		length = reste_msg[0] + "" + reste_msg[1]
		name = ""
		while(length != '00'):
			if is_data_label(reste_msg[0]):
				#print("Question name - label length: " + str(int(length, 16)) + " octets")
				label = ""
				for i in range(2, 2*(int(length, 16)+1)):
					label = label + "" + reste_msg[i]
				name = name + str(codecs.decode(label, "hex"), 'utf-8') + "."
				if not dico.get(pos):
					dico[pos] = []
				dico[pos].append(label)
				reste_msg = reste_msg[2*(int(length, 16)+1):]
				length = reste_msg[0] + "" + reste_msg[1]
			else:
				offset = 2*int(str(hexa_en_binaire(reste_msg[0] + "" + reste_msg[1] + "" + reste_msg[2] + "" + reste_msg[3]))[2:], 2)
				
				label_list = []
				if not dico.get(offset):
					key_list = [key for key in dico]
					for i in range(len(key_list)):
						if (int(key_list[i]) > int(offset)):
							c = key_list[i-1]
							break
					elem_deb = int(c)
					for i in range(1, len(dico[c])):
						elem_deb = elem_deb + len(dico[c][i-1]) + 2
						if (elem_deb == offset):
							label_list = dico[c][i:]
							break
				else:
					label_list = dico[offset]
				
				for el in label_list:
					#print("Question name - label length: " + str(int(len(el)/2)) + " octets")
					name = name + str(codecs.decode(el, "hex"), 'utf-8') + "."
					if not dico.get(pos):
						dico[pos] = []
					dico[pos].append(el)
				break
		print("\t\t‣ Name: " + name.rstrip("."))
		if length == '00':
			reste_msg = reste_msg[2:]
		else:
			reste_msg = reste_msg[4:]
		
		qtype = reste_msg[0] + "" + reste_msg[1] + "" + reste_msg[2] + "" + reste_msg[3]
		print("\t\t\t‣ Type: " + dns_types[qtype])
	
		qclass = reste_msg[4] + "" + reste_msg[5] + "" + reste_msg[6] + "" + reste_msg[7]
		print("\t\t\t‣ Class: IN")
		
		reste_msg = reste_msg[8:]
		
	#-------------------answ-----------------------------------------
	if int(nb_ans, 16) != 0:
		print("\t‣ Answers")
	for i in range(int(nb_ans, 16)):
		pos = find_sublist(reste_msg, msg_dns)
		length = reste_msg[0] + "" + reste_msg[1]
		name = ""
		while(length != '00'):
			if is_data_label(reste_msg[0]):
				#print("Answer name - label length: " + str(int(length, 16)) + " octets")
				label = ""
				for i in range(2, 2*(int(length, 16)+1)):
					label = label + "" + reste_msg[i]
				#print("Answer name - label value: " + str(codecs.decode(label, "hex"), 'utf-8'))
				name = name + str(codecs.decode(label, "hex"), 'utf-8') + "."
				if not dico.get(pos):
					dico[pos] = []
				dico[pos].append(label)
				reste_msg = reste_msg[2*(int(length, 16)+1):]
				length = reste_msg[0] + "" + reste_msg[1]
			else:
				offset = 2*int(str(hexa_en_binaire(reste_msg[0] + "" + reste_msg[1] + "" + reste_msg[2] + "" + reste_msg[3]))[2:], 2)
				
				label_list = []
				if not dico.get(offset):
					key_list = [key for key in dico]
					for i in range(len(key_list)):
						if (int(key_list[i]) > int(offset)):
							c = key_list[i-1]
							break
					elem_deb = int(c)
					for i in range(1, len(dico[c])):
						elem_deb = elem_deb + len(dico[c][i-1]) + 2
						if (elem_deb == offset):
							label_list = dico[c][i:]
							break
				else:
					label_list = dico[offset]
				
				for el in label_list:
					#print("Answer name - label length: " + str(int(len(el)/2)) + " octets")
					#print("Answer name - label value: " + str(codecs.decode(el, "hex"), 'utf-8'))
					name = name + str(codecs.decode(el, "hex"), 'utf-8') + "."
					if not dico.get(pos):
						dico[pos] = []
					dico[pos].append(el)
				break
		print("\t\t‣ Name: " + name.rstrip("."))
		if length == '00':
			reste_msg = reste_msg[2:]
		else:
			reste_msg = reste_msg[4:]
		
		atype = reste_msg[0] + "" + reste_msg[1] + "" + reste_msg[2] + "" + reste_msg[3]
		print("\t\t\t‣ Type: " + dns_types[atype])
	
		aclass = reste_msg[4] + "" + reste_msg[5] + "" + reste_msg[6] + "" + reste_msg[7]
		print("\t\t\t‣ Class: IN")
		
		ttl = reste_msg[8] + "" + reste_msg[9] + "" + reste_msg[10] + "" + reste_msg[11] + "" + reste_msg[12] + "" + reste_msg[13] + "" + reste_msg[14] + "" + reste_msg[15]
		print("\t\t\t‣ TTL: " + str(int(ttl, 16)) + "s")
		
		rdata_length = reste_msg[16] + "" + reste_msg[17] + "" + reste_msg[18] + "" + reste_msg[19]
		print("\t\t\t‣ Data length: " + str(int(rdata_length, 16)) + " bytes")
		
		reste_msg = reste_msg[20:]
		
		pos = find_sublist(reste_msg, msg_dns)
		length = reste_msg[0] + "" + reste_msg[1]
		
		if (atype == '0002' or atype == '0005' or atype.lower() == '000f'):
			rdata_f = ""
			while(length != '00'):
			
				if is_data_label(reste_msg[0]):
					#print("Answer rdata - label length: " + str(int(length, 16)) + " octets")
					label = ""
					for i in range(2, 2*(int(length, 16)+1)):
						label = label + "" + reste_msg[i]
					#print("Answer rdata - label value: " + str(codecs.decode(label, "hex"), 'utf-8'))
					rdata_f = rdata_f + str(codecs.decode(label, "hex"), 'utf-8') + "."
					if not dico.get(pos):
						dico[pos] = []
					dico[pos].append(label)
					reste_msg = reste_msg[2*(int(length, 16)+1):]
					length = reste_msg[0] + "" + reste_msg[1]
				else:
					offset = 2*int(str(hexa_en_binaire(reste_msg[0] + "" + reste_msg[1] + "" + reste_msg[2] + "" + reste_msg[3]))[2:], 2)
					
					label_list = []
					if not dico.get(offset):
						key_list = [key for key in dico]
						for i in range(len(key_list)):
							if (int(key_list[i]) > int(offset)):
								c = key_list[i-1]
								break
						elem_deb = int(c)
						for i in range(1, len(dico[c])):
							elem_deb = elem_deb + len(dico[c][i-1]) + 2
							if (elem_deb == offset):
								label_list = dico[c][i:]
								break
					else:
						label_list = dico[offset]
					
					for el in label_list:
						#print("Answer rdata - label length: " + str(int(len(el)/2)) + " octets")
						#print("Answer rdata - label value: " + str(codecs.decode(el, "hex"), 'utf-8'))
						rdata_f = rdata_f + str(codecs.decode(el, "hex"), 'utf-8') + "."
						if not dico.get(pos):
							dico[pos] = []
						dico[pos].append(el)
					break
			print("\t\t\t‣ Data: " + rdata_f.rstrip("."))
			if length == '00':
				reste_msg = reste_msg[2:]
			else:
				reste_msg = reste_msg[4:]
		else:
			rdata = ""
			for i in range(0, 2*int(rdata_length, 16), 2):
				rdata = rdata + "." + str(int(reste_msg[i] + "" + reste_msg[i+1], 16))
			rdata = rdata.lstrip(".")
			print("\t\t\t‣ Data: " + rdata)
			reste_msg = reste_msg[8:]
			
	#-------------------------------authority-----------------------
	if int(nb_auth, 16) != 0:
		print("\t‣ Authoritative nameservers")
	for i in range(int(nb_auth, 16)):
		pos = find_sublist(reste_msg, msg_dns)
		length = reste_msg[0] + "" + reste_msg[1]
		name = ""
		while(length != '00'):
			if is_data_label(reste_msg[0]):
				#print("Authority name - label length: " + str(int(length, 16)) + " octets")
				label = ""
				for i in range(2, 2*(int(length, 16)+1)):
					label = label + "" + reste_msg[i]
				#print("Authority name - label value: " + str(codecs.decode(label, "hex"), 'utf-8'))
				name = name + str(codecs.decode(label, "hex"), 'utf-8') + "."
				if not dico.get(pos):
					dico[pos] = []
				dico[pos].append(label)
				reste_msg = reste_msg[2*(int(length, 16)+1):]
				length = reste_msg[0] + "" + reste_msg[1]
			else:
				offset = 2*int(str(hexa_en_binaire(reste_msg[0] + "" + reste_msg[1] + "" + reste_msg[2] + "" + reste_msg[3]))[2:], 2)
				
				label_list = []
				if not dico.get(offset):
					key_list = [key for key in dico]
					for i in range(len(key_list)):
						if (int(key_list[i]) > int(offset)):
							c = key_list[i-1]
							break
					elem_deb = int(c)
					for i in range(1, len(dico[c])):
						elem_deb = elem_deb + len(dico[c][i-1]) + 2
						if (elem_deb == offset):
							label_list = dico[c][i:]
							break
				else:
					label_list = dico[offset]
				
				for el in label_list:
					#print("Authority name - label length: " + str(int(len(el)/2)) + " octets")
					#print("Authority name - label value: " + str(codecs.decode(el, "hex"), 'utf-8'))
					name = name + str(codecs.decode(el, "hex"), 'utf-8') + "."
					if not dico.get(pos):
						dico[pos] = []
					dico[pos].append(el)
				break
		print("\t\t‣ Name: " + name.rstrip("."))
		if length == '00':
			reste_msg = reste_msg[2:]
		else:
			reste_msg = reste_msg[4:]
		
		authtype = reste_msg[0] + "" + reste_msg[1] + "" + reste_msg[2] + "" + reste_msg[3]
		print("\t\t\t‣ Type: " + dns_types[authtype])
	
		authclass = reste_msg[4] + "" + reste_msg[5] + "" + reste_msg[6] + "" + reste_msg[7]
		print("\t\t\t‣ Class: IN")
		
		ttl = reste_msg[8] + "" + reste_msg[9] + "" + reste_msg[10] + "" + reste_msg[11] + "" + reste_msg[12] + "" + reste_msg[13] + "" + reste_msg[14] + "" + reste_msg[15]
		print("\t\t\t‣ TTL: " + str(int(ttl, 16)) + "s")
		
		rdata_length = reste_msg[16] + "" + reste_msg[17] + "" + reste_msg[18] + "" + reste_msg[19]
		print("\t\t\t‣ Data length: " + str(int(rdata_length, 16)) + " bytes")
		
		reste_msg = reste_msg[20:]
		
		pos = find_sublist(reste_msg, msg_dns)
		length = reste_msg[0] + "" + reste_msg[1]
		
		if (authtype == '0002' or authtype == '0005' or authtype.lower() == '000f'):
			rdata_f = ""
			while(length != '00'):
			
				if is_data_label(reste_msg[0]):
					#print("Authority rdata - label length: " + str(int(length, 16)) + " octets")
					label = ""
					for i in range(2, 2*(int(length, 16)+1)):
						label = label + "" + reste_msg[i]
					#print("Authority rdata - label value: " + str(codecs.decode(label, "hex"), 'utf-8'))
					rdata_f = rdata_f + str(codecs.decode(label, "hex"), 'utf-8') + "."
					if not dico.get(pos):
						dico[pos] = []
					dico[pos].append(label)
					reste_msg = reste_msg[2*(int(length, 16)+1):]
					length = reste_msg[0] + "" + reste_msg[1]
				else:
					offset = 2*int(str(hexa_en_binaire(reste_msg[0] + "" + reste_msg[1] + "" + reste_msg[2] + "" + reste_msg[3]))[2:], 2)
					
					label_list = []
					if not dico.get(offset):
						key_list = [key for key in dico]
						for i in range(len(key_list)):
							if (int(key_list[i]) > int(offset)):
								c = key_list[i-1]
								break
						elem_deb = int(c)
						for i in range(1, len(dico[c])):
							elem_deb = elem_deb + len(dico[c][i-1]) + 2
							if (elem_deb == offset):
								label_list = dico[c][i:]
								break
					else:
						label_list = dico[offset]
					
					for el in label_list:
						#print("Authority rdata - label length: " + str(int(len(el)/2)) + " octets")
						#print("Authority rdata - label value: " + str(codecs.decode(el, "hex"), 'utf-8'))
						rdata_f = rdata_f + str(codecs.decode(el, "hex"), 'utf-8') + "."
						if not dico.get(pos):
							dico[pos] = []
						dico[pos].append(el)
					break
			print("\t\t\t‣ Data: " + rdata_f.rstrip("."))
			if length == '00':
				reste_msg = reste_msg[2:]
			else:
				reste_msg = reste_msg[4:]
		else:
			rdata = ""
			for i in range(0, 2*int(rdata_length, 16), 2):
				rdata = rdata + "." + str(int(reste_msg[i] + "" + reste_msg[i+1], 16))
			rdata = rdata.lstrip(".")
			print("\t\t\t‣ Data: " + rdata)
			reste_msg = reste_msg[8:]
	#--------------fin authority------------------------------------
	
	#-------------------------------additional-----------------------
	if int(nb_quest, 16) != 0:
		print("\t‣ Additional records")
	for i in range(int(nb_add, 16)):
		pos = find_sublist(reste_msg, msg_dns)
		length = reste_msg[0] + "" + reste_msg[1]
		name = ""
		while(length != '00'):
			if is_data_label(reste_msg[0]):
				#print("Additional name - label length: " + str(int(length, 16)) + " octets")
				label = ""
				for i in range(2, 2*(int(length, 16)+1)):
					label = label + "" + reste_msg[i]
				#print("Additional name - label value: " + str(codecs.decode(label, "hex"), 'utf-8'))
				name = name + str(codecs.decode(label, "hex"), 'utf-8') + "."
				if not dico.get(pos):
					dico[pos] = []
				dico[pos].append(label)
				reste_msg = reste_msg[2*(int(length, 16)+1):]
				length = reste_msg[0] + "" + reste_msg[1]
			else:
				offset = 2*int(str(hexa_en_binaire(reste_msg[0] + "" + reste_msg[1] + "" + reste_msg[2] + "" + reste_msg[3]))[2:], 2)
				
				label_list = []
				if not dico.get(offset):
					key_list = [key for key in dico]
					for i in range(len(key_list)):
						if (int(key_list[i]) > int(offset)):
							c = key_list[i-1]
							break
					elem_deb = int(c)
					for i in range(1, len(dico[c])):
						elem_deb = elem_deb + len(dico[c][i-1]) + 2
						if (elem_deb == offset):
							label_list = dico[c][i:]
							break
				else:
					label_list = dico[offset]
				
				for el in label_list:
					#print("Additional name - label length: " + str(int(len(el)/2)) + " octets")
					#print("Additional name - label value: " + str(codecs.decode(el, "hex"), 'utf-8'))
					name = name + str(codecs.decode(el, "hex"), 'utf-8') + "."
					if not dico.get(pos):
						dico[pos] = []
					dico[pos].append(el)
				break
		print("\t\t‣ Name: " + name.rstrip("."))
		if length == '00':
			reste_msg = reste_msg[2:]
		else:
			reste_msg = reste_msg[4:]
		
		addtype = reste_msg[0] + "" + reste_msg[1] + "" + reste_msg[2] + "" + reste_msg[3]
		print("\t\t\t‣ Type: " + dns_types[addtype])
	
		addclass = reste_msg[4] + "" + reste_msg[5] + "" + reste_msg[6] + "" + reste_msg[7]
		print("\t\t\t‣ Class: IN")
		
		ttl = reste_msg[8] + "" + reste_msg[9] + "" + reste_msg[10] + "" + reste_msg[11] + "" + reste_msg[12] + "" + reste_msg[13] + "" + reste_msg[14] + "" + reste_msg[15]
		print("\t\t\t‣ TTL: " + str(int(ttl, 16)) + "s")
		
		rdata_length = reste_msg[16] + "" + reste_msg[17] + "" + reste_msg[18] + "" + reste_msg[19]
		print("\t\t\t‣ Data length: " + str(int(rdata_length)) + " bytes")
		
		reste_msg = reste_msg[20:]
		
		pos = find_sublist(reste_msg, msg_dns)
		length = reste_msg[0] + "" + reste_msg[1]
		
		if (addtype == '0002' or addtype == '0005' or addtype.lower() == '000f'):
			rdata_f = ""
			while(length != '00'):
			
				if is_data_label(reste_msg[0]):
					#print("Additional rdata - label length: " + str(int(length, 16)) + " octets")
					label = ""
					for i in range(2, 2*(int(length, 16)+1)):
						label = label + "" + reste_msg[i]
					#print("Additional rdata - label value: " + str(codecs.decode(label, "hex"), 'utf-8'))
					rdata_f = rdata_f + str(codecs.decode(label, "hex"), 'utf-8') + "."
					if not dico.get(pos):
						dico[pos] = []
					dico[pos].append(label)
					reste_msg = reste_msg[2*(int(length, 16)+1):]
					length = reste_msg[0] + "" + reste_msg[1]
				else:
					offset = 2*int(str(hexa_en_binaire(reste_msg[0] + "" + reste_msg[1] + "" + reste_msg[2] + "" + reste_msg[3]))[2:], 2)
					
					label_list = []
					if not dico.get(offset):
						key_list = [key for key in dico]
						for i in range(len(key_list)):
							if (int(key_list[i]) > int(offset)):
								c = key_list[i-1]
								break
						elem_deb = int(c)
						for i in range(1, len(dico[c])):
							elem_deb = elem_deb + len(dico[c][i-1]) + 2
							if (elem_deb == offset):
								label_list = dico[c][i:]
								break
					else:
						label_list = dico[offset]
					
					for el in label_list:
						#print("Additional rdata - label length: " + str(int(len(el)/2)) + " octets")
						#print("Additional rdata - label value: " + str(codecs.decode(el, "hex"), 'utf-8'))
						rdata_f = rdata_f + str(codecs.decode(el, "hex"), 'utf-8') + "."
						if not dico.get(pos):
							dico[pos] = []
						dico[pos].append(el)
					break
			print("\t\t\t‣ Name: " + rdata_f.rstrip("."))
			if length == '00':
				reste_msg = reste_msg[2:]
			else:
				reste_msg = reste_msg[4:]
		else:
			rdata = ""
			for i in range(0, 2*int(rdata_length, 16), 2):
				rdata = rdata + "." + str(int(reste_msg[i] + "" + reste_msg[i+1], 16))
			rdata = rdata.lstrip(".")
			print("\t\t\t‣ Data: " + rdata)
			reste_msg = reste_msg[8:]
	#--------------fin additional------------------------------------
	
#--------------debut dhcp------------------------------------

def decodage_msg_dhcp(msg_dhcp, data_length):
	print("‣ Dynamic Host Configuration Protocol (DHCP)")
	
	opcode = msg_dhcp[0] + "" + msg_dhcp[1]
	print("\t‣ Message type: " + dhcp_opcode[opcode] + " (" + str(int(opcode, 16)) + ")")
	
	hdw_type = "01"
	print("\t‣ Hardware type: Ethernet (0x" + hdw_type + ")")
	
	hdw_adress_length = "06"
	print("\t‣ Hardware adress length: " + str(int(hdw_adress_length, 16)))
	
	hops = msg_dhcp[6] + "" + msg_dhcp[7]
	print("\t‣ Hops: " + str(int(hops, 16)))
	
	transac_id = ""
	for i in range(8, 16):
		transac_id = transac_id + "" + msg_dhcp[i]
	print("\t‣ Transaction ID: 0x" + transac_id)
	
	nb_seconds = msg_dhcp[16] + "" + msg_dhcp[17] + "" + msg_dhcp[18] + "" + msg_dhcp[19]
	print("\t‣ Seconds elapsed: " + str(int(nb_seconds, 16)))
	
	flags = msg_dhcp[20] + "" + msg_dhcp[21] + "" + msg_dhcp[22] + "" + msg_dhcp[23]
	cast = "\t‣ Broadcast" if (hexa_en_binaire(flags)[0] == 1) else "Unicast"
	print("\t‣ Bootp flags: 0x" + flags + " (" + cast + ")")
	
	client_ip = ""
	for i in range(24, 31, 2):
		client_ip = client_ip + "." + str(int(msg_dhcp[i] + "" + msg_dhcp[i+1], 16))
	client_ip = client_ip.lstrip(".")
	print("\t‣ Client IP address: " + client_ip)
	
	your_ip = ""
	for i in range(32, 39, 2):
		your_ip = your_ip + "." + str(int(msg_dhcp[i] + "" + msg_dhcp[i+1], 16))
	your_ip = your_ip.lstrip(".")
	print("\t‣ Your (client) IP address: " + your_ip)
	
	server_ip = ""
	for i in range(40, 47, 2):
		server_ip = server_ip + "." + str(int(msg_dhcp[i] + "" + msg_dhcp[i+1], 16))
	server_ip = server_ip.lstrip(".")
	print("\t‣ Next server IP address: " + server_ip)
	
	gateway_ip = ""
	for i in range(48, 55, 2):
		gateway_ip = gateway_ip + "." + str(int(msg_dhcp[i] + "" + msg_dhcp[i+1], 16))
	gateway_ip = gateway_ip.lstrip(".")
	print("\t‣ Relay agent IP address: " + gateway_ip)
	
	client_mac = ""
	for i in range(56, 67, 2):
		client_mac = client_mac + ":" + msg_dhcp[i] + "" + msg_dhcp[i+1]
	client_mac = client_mac.lstrip(":")
	print("\t‣ Client MAC address: " + client_mac)
	
	server_name = ""
	for i in range(87, 215):
		server_name = server_name + "" + msg_dhcp[i]
	server_name = str(codecs.decode(server_name, "hex"), 'utf-8')
	print("\t‣ Server host name: " + (server_name if (not server_name) else "not given"))
	
	boot_file = ""
	for i in range(216, 472):
		boot_file = boot_file + "" + msg_dhcp[i]
	boot_file = str(codecs.decode(boot_file, "hex"), 'utf-8')
	print("\t‣ Boot file name: " + (boot_file if (not boot_file) else "not given"))
	
	magic_cookie = "63825363"
	print("\t‣ Magic cookie: DHCP")
	
	if data_length>236+4:
		reste_msg = msg_dhcp[480:]
		t = reste_msg[0] + "" + reste_msg[1]
		print("\t‣ Option: (" + str(int(t, 16)) + ") " + types_options_dhcp[str(int(t, 16))])
		while(int(t, 16) != 255):
			if (t != '00' and t!=  '50' and t != 'ff' and int(t,16) not in range(224, 255)):
				l = reste_msg[2] + "" + reste_msg[3]
				print("\t\t‣ Length: " + str(int(l, 16)) + " bytes")
				l = int(l, 16)
				val = ""
				for i in range(4, 4+l*2 - 1, 2):
					val = val + "" + reste_msg[i] + "" + reste_msg[i+1]
				print("\t\t‣ " + details_option_dhcp(int(t, 16), val))
				del reste_msg [:4+l*2]
			if (int(t,16) in range(224, 255)):
				l = str(int(reste_msg[2] + "" + reste_msg[3], 16))
				del reste_msg [:4+l*2]
			t = reste_msg[0] + "" + reste_msg[1]
			print("\t‣ Option: (" + str(int(t, 16)) + ") " + types_options_dhcp[str(int(t, 16))])
	
	#print(reste_msg)
	
#--------------fin dhcp------------------------------------

def details_option_dhcp(t, val):
	if t == 1:
		temp = "Subnet mask: "
		for i in range(0, 7, 2):
			temp = temp + str(int(val[i] + "" + val[i+1], 16)) + "."
		return temp.rstrip(".")
	elif t == 3:
		temp = "Router: "
		for i in range(0, 7, 2):
			temp = temp + str(int(val[i] + "" + val[i+1], 16)) + "."
		return temp.rstrip(".")
	elif t == 6:
		temp = "Domain name server: "
		for i in range(0, 7, 2):
			temp = temp + str(int(val[i] + "" + val[i+1], 16)) + "."
		return temp.rstrip(".")
	elif t == 12:
		return "Host name: " + str(codecs.decode(val, "hex"), 'utf-8')
	elif t == 43:
		return "Information: 0x" + val
	elif t == 50:
		temp = "Requested IP address: "
		for i in range(0, 7, 2):
			temp = temp + str(int(val[i] + "" + val[i+1], 16)) + "."
		return temp.rstrip(".")
	elif t == 51:
		return "IP address lease time: (" + str(int(val, 16)) + "s) " + str(int(val, 16)//3600) + " hours"
	elif t == 53:
		return "Message type: " + dhcp_message_types[val]
	elif t == 54:
		temp = "Server identifier: "
		for i in range(0, 7, 2):
			temp = temp + str(int(val[i] + "" + val[i+1], 16)) + "."
		return temp.rstrip(".")
	elif t == 55:
		temp = "Parameter Request List Item: (" + str(int(val[0] + val[1], 16)) + ") " + types_options_dhcp[str(int(val[0] + val[1], 16))] + "\n"
		for i in range(2, len(val)-1, 2):
			temp = temp + "\t\t‣ Parameter Request List Item: (" + str(int(val[i] + val[i+1], 16)) + ") " + types_options_dhcp[str(int(val[i] + val[i+1], 16))] + "\n"
		return temp.rstrip("\n")
	elif t == 58:
		return "Renewal time value: (" + str(int(val, 16)) + "s) " + str(int(val, 16)//3600) + " hours"
	elif t == 59:
		return "Rebinding time value: (" + str(int(val, 16)) + "s) " + str(int(val, 16)//3600) + " hours"
	elif t == 60:
		return "Vendor class identifier: " + str(codecs.decode(val, "hex"), 'utf-8')
	elif t == 61:
		temp = "Hardware type: Ethernet (0x01)\n\t\t‣ Client MAC address: "
		for i in range(2, 13, 2):
			temp = temp + val[i] + "" + val[i+1] + ":"
		return temp.rstrip(":")
	elif t == 81:
		flags = "Flags: 0x" + val[0] + "" + val[1] + "\n\t\t\t‣ Reserved flags: 0x0\n\t\t\t‣ Server DDNS: " + ("Some server updates" if hexa_en_binaire(val[1])[0] == "0" else "No server updates") + " (" + hexa_en_binaire(val[1])[0] + ")\n\t\t\t‣ Encoding: " + ("ASCII" if hexa_en_binaire(val[1])[0] == "0" else "canonical wire format without compression") + " (" + hexa_en_binaire(val[1])[0] + ")\n\t\t\t‣ Server overrides: " + ("no" if hexa_en_binaire(val[1])[0] == "0" else "yes") + " (" + hexa_en_binaire(val[1])[0] + ")\n\t\t\t‣ A RR DNS updates: " + ("no" if hexa_en_binaire(val[1])[0] == "0" else "yes") + " (" + hexa_en_binaire(val[1])[0] + ")"
		a_rr = "\t\t‣ A-RR result: " + str(int(val[2] + "" + val[3], 16))
		ptr_rr = "\t\t‣ PTR-RR result: " + str(int(val[4] + "" + val[5], 16))
		return flags + "\n" + a_rr + "\n" + ptr_rr
	elif t == 116:
		return ("Auto-configuration: " + ("enabled" if val=="01" else "disabled") + " (" + str(int(val, 16)) + ")")
	else:
		return "Value: " + val
		

# test
with open('resultat.txt','w') as f:
	with contextlib.redirect_stdout(f):
		frame_list = lire_trace(sys.argv[1])
		for frame in frame_list:
			liste_octets = []
			for line in frame:
				for byte in line:
					liste_octets.append(byte)
			liste_chiffres_h = liste_chiffres(liste_octets)
			entete_ethernet = obtenir_octets(liste_octets, 0, 14)

			decodage_entete_ethernet(entete_ethernet)
			print("")
			suite = decodage_entete_ip(liste_octets)
			print("")
			entete_udp = liste_chiffres_h[suite+1:suite+1+16]
			(data_length, port) = decodage_entete_udp(entete_udp)
			print("")
			if (port == 53):
				msg_dns = liste_chiffres_h[suite+1+16:]
				decodage_msg_dns(msg_dns)
			elif (port == 67 or port == 68):
				msg_dhcp = liste_chiffres_h[suite+1+16:]
				decodage_msg_dhcp(msg_dhcp, data_length)
			print("\n-----------------------------------------------------------------\n")
