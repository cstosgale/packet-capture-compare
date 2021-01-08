import csv
import json
import sys
from os import listdir
from jsonextract import json_extract

path = ''
source = 'workstation capture.json'
destination = 'firewall capture.json'

def import_cap(path, filename):
	# Define local variables
	cap_dict = {}
	# Read the capture and extract the required parameters into separate lists
	jfile = open(path + filename)
	contents = jfile.read()
	jblock = json.loads(contents)
	ipsrc = json_extract(jblock, 'ip.src')
	ipdst = json_extract(jblock, 'ip.dst')
	tcpsrcport = json_extract(jblock, 'tcp.srcport')
	tcpdstport = json_extract(jblock, 'tcp.dstport')
	tcpseq = json_extract(jblock, 'tcp.seq')
	tcpnxtseq = json_extract(jblock, 'tcp.nxtseq')
	tcpflagssyn = json_extract(jblock, 'tcp.flags.syn')
	tcpflagsack = json_extract(jblock, 'tcp.flags.ack')
	tcpflagsreset = json_extract(jblock, 'tcp.flags.reset')

	#Combine the different lists into a single dictionary
	for index in range(len(ipsrc)):
		try:
			cap_dict[index] = {}
			cap_dict[index]['ip.src'] = ipsrc[index]
			cap_dict[index]['ip.dst'] = ipdst[index]
			cap_dict[index]['tcp.srcport'] = tcpsrcport[index]
			cap_dict[index]['tcp.dstport'] = tcpdstport[index]
			cap_dict[index]['tcp.seq'] = tcpseq[index]
			cap_dict[index]['tcp.nxtseq'] = tcpnxtseq[index]
			cap_dict[index]['tcp.flags.syn'] = tcpflagssyn[index]
			cap_dict[index]['tcp.flags.ack'] = tcpflagsack[index]
			cap_dict[index]['tcp.flags.reset'] = tcpflagsreset[index]
		
		except Exception as e:
			print ('Error: ', e, '\n', 'Index: ', index)
	return cap_dict

def cap_concat(cap_dict, index):
	# Concatenate the unique packet values from the dictionary
	concat = cap_dict[index]['ip.src'] + cap_dict[index]['ip.dst'] + cap_dict[index]['tcp.srcport'] + cap_dict[index]['tcp.dstport'] + cap_dict[index]['tcp.seq'] + cap_dict[index]['tcp.nxtseq'] + cap_dict[index]['tcp.flags.syn'] + cap_dict[index]['tcp.flags.ack'] + cap_dict[index]['tcp.flags.reset']
	return concat

#print files

#csvfile = csv.writer(open("results.csv", "w+"))


# Write CSV Header, If you dont need that, remove this line
#csvfile.writerow(["SrcIP", "DestIP", "SrcPort", "DstPort", "Seq", "Nxtseq", "Syn", "Ack", "Rst"])

#print ["Account", "Alias", "Origin"]

#for filename in files:

	
#	account = filename.split(".")[0]

srccap_dict = import_cap(path, source)
dstcap_dict = import_cap(path, destination)

for srcindex in range(len(srccap_dict)):
	srcconcat = cap_concat(srccap_dict, srcindex)
	for dstindex in range(len(dstcap_dict)):
		dstconcat = cap_concat(dstcap_dict, dstindex)
		if srcconcat == dstconcat:
			srccap_dict[srcindex]['packetatdest'] = 'Yes'
			break
		else:
			srccap_dict[srcindex]['packetatdest'] = 'No'
	print(srccap_dict[srcindex])