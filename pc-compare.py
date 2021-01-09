import csv
import json
import sys
import datetime
#import XlsXWriter
from os import listdir
from jsonextract import json_extract
from collections import OrderedDict 
from operator import itemgetter

#Config Variables
path = ''
clientjson = 'client capture.json'
serverjson = 'firewall capture.json'
wbname = 'cap-analysis.xlsx'
clientconcat_list = []
cap_schema = ['frame.time', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'tcp.seq', 'tcp.nxtseq', 'tcp.flags.syn', 'tcp.flags.ack', 'tcp.flags.ack', 'tcp.flags.reset']

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
	for sitem in cap_schema:
		index = 0
		for jitem in json_extract(jblock, sitem):
			index += 1
			if len(cap_dict) < index:
				cap_dict[index] = {}
			cap_dict[index][sitem] = jitem
	return cap_dict

def cap_concat(cap_dict, index):
	# Concatenate the unique packet values from the dictionary
	concat = cap_dict[index]['tcp.srcport'] + cap_dict[index]['tcp.dstport'] + cap_dict[index]['tcp.seq'] + cap_dict[index]['tcp.nxtseq'] + cap_dict[index]['tcp.flags.syn'] + cap_dict[index]['tcp.flags.ack'] + cap_dict[index]['tcp.flags.reset']
	return concat
	
# def write_xlsx(wbname):
# 	# Create a workbook and add a worksheet.
# 	workbook = xlsxwriter.Workbook(wbname)
# 	worksheet = workbook.add_worksheet()
# 
# 	# Start from the first cell. Rows and columns are zero indexed.
# 	row = 0
# 	col = 0
# 
# 	# Iterate over the data and write it out row by row.
# 	for item, cost in (expenses):
# 		worksheet.write(row, col, item)
# 		worksheet.write(row, col + 1, cost)
# 		row += 1

# Write a total using a formula.
# worksheet.write(row, 0, 'Total')
# worksheet.write(row, 1, '=SUM(B1:B4)')
# 
# workbook.close()

#Import the captures into two dictionaries
clientcap_dict = import_cap(path, clientjson)
servercap_dict = import_cap(path, serverjson)


compcap_dict = clientcap_dict

print(clientcap_dict[1])

for clientindex in range(len(clientcap_dict)):
	if clientindex != 0:
		clientconcat = cap_concat(clientcap_dict, clientindex)
		for serverindex in range(len(servercap_dict)):
			if serverindex != 0:
				serverconcat = cap_concat(servercap_dict, serverindex)
				if clientconcat == serverconcat:
					clientcap_dict[clientindex]['packetatclient'] = 'Yes'
					clientcap_dict[clientindex]['packetatsvr'] = 'Yes'
					compcap_dict[clientindex]['packetatclient'] = 'Yes'
					compcap_dict[clientindex]['packetatsvr'] = 'Yes'
					break
				else:
					clientcap_dict[clientindex]['packetatclient'] = 'Yes'
					clientcap_dict[clientindex]['packetatsvr'] = 'No'
					compcap_dict[clientindex]['packetatclient'] = 'Yes'
					compcap_dict[clientindex]['packetatsvr'] = 'No'

#Create a list containing all the client packet concatinations
for clientindex in range(len(clientcap_dict)):
	if clientindex != 0:
		clientconcat_list.append(cap_concat(clientcap_dict, clientindex))

#Check if the server packet does not exist in the client
for serverindex in range(len(servercap_dict)):
	if serverindex != 0:	
		serverconcat = cap_concat(servercap_dict, serverindex)
		if serverconcat not in clientconcat_list:
			servercap_dict[serverindex]['packetatclient'] = 'No'
			servercap_dict[serverindex]['packetatsvr'] = 'Yes'
			compindex = len(compcap_dict)
			compcap_dict[compindex] = servercap_dict[serverindex]

#Sort the output by the packet timestamps
compcap_dict = sorted(compcap_dict.values(), key=itemgetter('frame.time'))


for index in range(len(compcap_dict)):
	if compcap_dict[index]['packetatsvr'] == 'Yes':
		print(compcap_dict[index])
	


#print files

#csvfile = csv.writer(open("results.csv", "w+"))


# Write CSV Header, If you dont need that, remove this line
#csvfile.writerow(["clientIP", "DestIP", "clientPort", "serverPort", "Seq", "Nxtseq", "Syn", "Ack", "Rst"])

#print ["Account", "Alias", "Origin"]

#for filename in files:

	
#	account = filename.split(".")[0]