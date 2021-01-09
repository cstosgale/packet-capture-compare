import csv
import json
import sys
import datetime
from os import listdir
from jsonextract import json_extract

path = ''
clientjson = 'client cap missing packet.json'
serverjson = 'firewall cap.json'
clientconcat_list = []

def ftime_datetime(string):
	#Converts the frame.time string formatted as "Jan  9, 2021 11:12:52.206763000 GMT Standard Time" to datetime
	i = 0
	datetimestr = ''
	datetime_obj = datetime.datetime.now()
	#Ensure the date includes a 0
	string = string.replace('  ', ' 0')
	#Removes the time zone and additional ms digits from the end of the string
	string = string[:-len(string)+28]
	try:
		datetime_obj = datetime.datetime.strptime(string, '%b %d, %Y %H:%M:%S.%f')
	except Exception as e:
		print('Datetime format error: ',e)
	return datetime_obj

def import_cap(path, filename):
	# Define local variables
	cap_dict = {}
	# Read the capture and extract the required parameters into separate lists
	jfile = open(path + filename)
	contents = jfile.read()
	jblock = json.loads(contents)
	frametime = json_extract(jblock, 'frame.time')
	ipclient = json_extract(jblock, 'ip.client')
	ipserver = json_extract(jblock, 'ip.server')
	tcpclientport = json_extract(jblock, 'tcp.clientport')
	tcpserverport = json_extract(jblock, 'tcp.serverport')
	tcpseq = json_extract(jblock, 'tcp.seq')
	tcpnxtseq = json_extract(jblock, 'tcp.nxtseq')
	tcpflagssyn = json_extract(jblock, 'tcp.flags.syn')
	tcpflagsack = json_extract(jblock, 'tcp.flags.ack')
	tcpflagsreset = json_extract(jblock, 'tcp.flags.reset')

	#Combine the different lists into a single dictionary
	for index in range(len(ipclient)):
		try:
			cap_dict[index] = {}
			cap_dict[index]['frame.date'] = ftime_datetime(frametime[index])
			cap_dict[index]['ip.client'] = ipclient[index]
			cap_dict[index]['ip.server'] = ipserver[index]
			cap_dict[index]['tcp.clientport'] = tcpclientport[index]
			cap_dict[index]['tcp.serverport'] = tcpserverport[index]
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
	concat = cap_dict[index]['tcp.clientport'] + cap_dict[index]['tcp.serverport'] + cap_dict[index]['tcp.seq'] + cap_dict[index]['tcp.nxtseq'] + cap_dict[index]['tcp.flags.syn'] + cap_dict[index]['tcp.flags.ack'] + cap_dict[index]['tcp.flags.reset']
	return concat

#Import the captures into two dictionaries
clientcap_dict = import_cap(path, clientjson)
servercap_dict = import_cap(path, serverjson)

compcap_dict = clientcap_dict

for clientindex in range(len(clientcap_dict)):
	clientconcat = cap_concat(clientcap_dict, clientindex)
	for serverindex in range(len(servercap_dict)):
		serverconcat = cap_concat(servercap_dict, serverindex)
		if clientconcat == serverconcat:
			clientcap_dict[clientindex]['packetatclient'] = 'Yes'
			clientcap_dict[clientindex]['packetatdest'] = 'Yes'
			compcap_dict[clientindex]['packetatclient'] = 'Yes'
			compcap_dict[clientindex]['packetatdest'] = 'Yes'
			break
		else:
			clientcap_dict[clientindex]['packetatclient'] = 'Yes'
			clientcap_dict[clientindex]['packetatdest'] = 'No'
			compcap_dict[clientindex]['packetatclient'] = 'Yes'
			compcap_dict[clientindex]['packetatdest'] = 'No'

#Create a list containing all the client packet concatinations
for clientindex in range(len(clientcap_dict)):
	clientconcat_list.append(cap_concat(clientcap_dict, clientindex))

#Check if the server packet does not exist in the client
for serverindex in range(len(servercap_dict)):
	serverconcat = cap_concat(servercap_dict, serverindex)
	if serverconcat not in clientconcat_list:
		servercap_dict[serverindex]['packetatclient'] = 'No'
		servercap_dict[serverindex]['packetatdest'] = 'Yes'
		compindex = len(compcap_dict)
		print(compindex)
		compcap_dict[compindex] = servercap_dict[serverindex]

for index in range(len(compcap_dict)):
	print(compcap_dict[index])

#print files

#csvfile = csv.writer(open("results.csv", "w+"))


# Write CSV Header, If you dont need that, remove this line
#csvfile.writerow(["clientIP", "DestIP", "clientPort", "serverPort", "Seq", "Nxtseq", "Syn", "Ack", "Rst"])

#print ["Account", "Alias", "Origin"]

#for filename in files:

	
#	account = filename.split(".")[0]