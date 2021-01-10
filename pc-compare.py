import csv
import json
import sys
import datetime
import xlsxwriter
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
cap_schema = ['frame.time', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'tcp.seq', 'tcp.nxtseq', 'tcp.flags.syn', 'tcp.flags.ack', 'tcp.flags.reset']

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
			if sitem == 'frame.time':
				cap_dict[index][sitem] = ftime_datetime(jitem)
			else:
				cap_dict[index][sitem] = jitem
	return cap_dict

def cap_concat(cap_dict, index):
	# Concatenate the unique packet values from the dictionary
	concat = cap_dict[index]['tcp.srcport'] + cap_dict[index]['tcp.dstport'] + cap_dict[index]['tcp.seq'] + cap_dict[index]['tcp.nxtseq'] + cap_dict[index]['tcp.flags.syn'] + cap_dict[index]['tcp.flags.ack'] + cap_dict[index]['tcp.flags.reset']
	return concat

def write_xlsx(cap_dict):
	headers_dict = {}
	
	# Add a worksheet.
	worksheet = workbook.add_worksheet()
	
	# Start from the first cell. Rows and columns are zero indexed.
	lastrow = len(cap_dict)
	lastcolumn = len(cap_schema) - 1
	
	#Creates a list of dictionaries containing the headers for the XLSX table, and applies any required formatting
	datetime_format = workbook.add_format()
	datetime_format.set_num_format('dd/mm/yyyy hh:mm')
	for index in range(len(cap_schema)):
		headers_dict[index] = {}
		headers_dict[index]['header'] = cap_schema[index]
		if cap_schema[index] == 'frame.time':
			headers_dict[index]['format'] = datetime_format
#	print(headers_dict)
	data = [list(col) for col in zip(*[d.values() for d in cap_dict])]
# 	for index in range(len(cap_dict)):
# 		if index != 0:
# 			for item in cap_schema:
# 				worksheet.write(row, col, cap_dict[index][item])		
# 	# Adds a table and writes out the headers
	worksheet.add_table(0, 0, lastrow, lastcolumn, {'data': data, 'columns': headers_dict})

	# Write out the headers - this has to be done after the table formatting so it doesn't get overwritten
# 	row = 0
# 	col = 0
# 	for item in cap_schema:
# 		worksheet.write(row, col, item)
# 		col += 1
	# Write out the data
	row = 1
	col = 0
	for index in range(len(cap_dict)):
		if index != 0:
			for item in cap_schema:
				worksheet.write(row, col, cap_dict[index][item])
				col += 1
			col = 0
			row += 1

#Import the captures into two dictionaries
print('Importing captures')
clientcap_dict = import_cap(path, clientjson)
servercap_dict = import_cap(path, serverjson)

#Perform the comparison between the two captures
print('Comparing captures')
compcap_dict = clientcap_dict

#Mark the packets first based on if the client packets exist in the server capture, and then the other way round
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


# for index in range(len(compcap_dict)):
# 	if compcap_dict[index]['packetatsvr'] == 'Yes':
# 		print(compcap_dict[index])
	
#Create the XLSX file and write the data
print('Writing the output to ', wbname)
workbook = xlsxwriter.Workbook(wbname)
#Add the additional fields needed in the scema for the output
cap_schema.append('packetatclient')
cap_schema.append('packetatsvr')
write_xlsx(compcap_dict)
workbook.close()