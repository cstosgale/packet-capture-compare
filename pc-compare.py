import csv
import json
import sys
import datetime
from os import listdir
from jsonextract import json_extract

path = ''
source = 'client cap.json'
destination = 'firewall cap.json'

def ftime_datetime(string):
	#Converts the frame.time string formatted as "Jan  9, 2021 11:12:52.206763000 GMT Standard Time" to datetime
	i = 0
	datetimestr = ''
	datetime_obj = datetime.datetime.now()
	print(string)
	splitstr = string.split(' ')
	print(splitstr)
	while i > 5:
		try:
			i += 1
			if i == 2 and len(splitstr[i]) == 1  :
				
				datetimestr += '0' + splitstr[i] + ' '
			else:
				print(splitstr)
				datetimestr += + splitstr[i] + ' '
		except Exception as e:
			print('Datetime format error: ',e)
	print(datetimestr)
#	datetime_obj = datetime.datetime.strptime(datetimestr, '%b %d, %H:%m:%d:%S.%f')
#	print(datetime_obj)
	return datetime_obj

def import_cap(path, filename):
	# Define local variables
	cap_dict = {}
	# Read the capture and extract the required parameters into separate lists
	jfile = open(path + filename)
	contents = jfile.read()
	jblock = json.loads(contents)
	frametime = json_extract(jblock, 'frame.time')
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
			cap_dict[index]['frame.time'] = ftime_datetime(frametime[index])
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
	concat = cap_dict[index]['tcp.srcport'] + cap_dict[index]['tcp.dstport'] + cap_dict[index]['tcp.seq'] + cap_dict[index]['tcp.nxtseq'] + cap_dict[index]['tcp.flags.syn'] + cap_dict[index]['tcp.flags.ack'] + cap_dict[index]['tcp.flags.reset']
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

print(srccap_dict[2])
print(dstcap_dict[2])

for srcindex in range(len(srccap_dict)):
	srcconcat = cap_concat(srccap_dict, srcindex)
	for dstindex in range(len(dstcap_dict)):
		dstconcat = cap_concat(dstcap_dict, dstindex)
		if srcconcat == dstconcat:
			srccap_dict[srcindex]['packetatdest'] = 'Yes'
			break
		else:
			srccap_dict[srcindex]['packetatdest'] = 'No'
	#print(srccap_dict[srcindex])