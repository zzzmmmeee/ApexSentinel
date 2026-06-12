import time
import pandas as pd
import numpy as np
import os
import os.path as osp
import csv
import re

def show(str):
	print (str + ' ' + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
 
pattern_uuid = re.compile(r'uuid\":\"(.*?)\"') 
pattern_src = re.compile(r'subject\":{\"com.bbn.tc.schema.avro.cdm18.UUID\":\"(.*?)\"}')
pattern_cmd = re.compile(r'cmdLine\":{\"string\":\"(.*?)\"}') 
pattern_file = re.compile(r'filename\":\"(.*?)\"') 
pattern_dst1 = re.compile(r'predicateObject\":{\"com.bbn.tc.schema.avro.cdm18.UUID\":\"(.*?)\"}')
pattern_dst2 = re.compile(r'predicateObject2\":{\"com.bbn.tc.schema.avro.cdm18.UUID\":\"(.*?)\"}')
pattern_dstpath1 = re.compile(r'predicateObjectPath\":\"(.*?)\"') 
pattern_dstpath2 = re.compile(r'predicateObject2Path\":\"(.*?)\"') 
pattern_type = re.compile(r'type\":\"(.*?)\"')
pattern_time = re.compile(r'timestampNanos\":(.*?),')
pattern_address = re.compile(r'remoteAddress\":\"(.*?)\"') 
pattern_port = re.compile(r'remotePort\":\"(.*?)\"') 

notice_num = 1000000
 
path = "ta1-theia-e3-official-6r.json" 
id_nodetype_map = {}
for i in range(100):
	now_path  = path + '.' + str(i)
	if i == 0: now_path = path
	if not osp.exists(now_path): break
	f = open(now_path, 'r')
	show(now_path)
	cnt  = 0
	for line in f:
		cnt += 1
		if cnt % notice_num == 0:
			print(cnt)
		if 'com.bbn.tc.schema.avro.cdm18.Event' in line or 'com.bbn.tc.schema.avro.cdm18.Host' in line: continue
		if 'com.bbn.tc.schema.avro.cdm18.TimeMarker' in line or 'com.bbn.tc.schema.avro.cdm18.StartMarker' in line: continue
		if 'com.bbn.tc.schema.avro.cdm18.UnitDependency' in line or 'com.bbn.tc.schema.avro.cdm18.EndMarker' in line: continue
		if len(pattern_uuid.findall(line)) == 0: print (line)
		uuid = pattern_uuid.findall(line)[0]
		if uuid == "00000000-0000-0000-0000-000000000000":
			id_nodetype_map[uuid]= 'unknown'
			continue
		subject_type = pattern_type.findall(line)
		if len(subject_type) < 1:
			if 'com.bbn.tc.schema.avro.cdm18.MemoryObject' in line:
				id_nodetype_map[uuid] = 'MemoryObject'
				continue
			if 'com.bbn.tc.schema.avro.cdm18.NetFlowObject' in line:
				address = pattern_address.findall(line)
				port = pattern_port.findall(line)
				if len(address)!=0 and len(port) !=0:
					id_nodetype_map[uuid] = 'NetFlowObject'+' '+address[0]+':'+port[0]
				elif len(address)!=0:
					id_nodetype_map[uuid] = 'NetFlowObject'+' '+address[0]
				else:
					id_nodetype_map[uuid] = 'NetFlowObject'
				continue
			if 'com.bbn.tc.schema.avro.cdm18.UnnamedPipeObject' in line:
				id_nodetype_map[uuid] = 'UnnamedPipeObject'
				continue
		cmd = pattern_cmd.findall(line)
		file_name = pattern_file.findall(line)
		if len(cmd) == 0: 
			cmd=' '
		else: 
			cmd = '"' + cmd[0][:50] + '"'
		if len(file_name) == 0: 
			file_name=' '
		else: 
			file_name = '"' + file_name[0][:50] + '"'
		if file_name==' ':
			id_nodetype_map[uuid] = subject_type[0]+' '+cmd
		else:
			id_nodetype_map[uuid] = subject_type[0]+' '+file_name
	print(cnt)
not_in_cnt = 0
for i in range(100):
	now_path  = path + '.' + str(i)
	if i == 0: now_path = path
	if not osp.exists(now_path): break
	if i != 3: continue
  
	f = open(now_path, 'r')
	show(now_path)
	fw = open("ta1-theia-e3-official-6r.json.3.txt", 'w')#open(now_path+'.txt', 'w')
	cnt = 0
	for line in f:
		cnt += 1
		if cnt % notice_num == 0:
			print(cnt) 

		if 'com.bbn.tc.schema.avro.cdm18.Event' in line:
			pattern = re.compile(r'subject\":{\"com.bbn.tc.schema.avro.cdm18.UUID\":\"(.*?)\"}')
			edgeType = pattern_type.findall(line)[0]
			timestamp = pattern_time.findall(line)[0]
			srcId = pattern_src.findall(line)
			if len(srcId) == 0: continue
			srcId = srcId[0]
			if not srcId in id_nodetype_map.keys(): 
				not_in_cnt += 1
				continue
			srcType = id_nodetype_map[srcId]
			dstId1 = pattern_dst1.findall(line)
			dstpath1 = pattern_dstpath1.findall(line)
			if len(dstId1) > 0  and dstId1[0] != 'null':
				dstId1 = dstId1[0]
				if len(dstpath1) > 0  and dstpath1[0] != 'null':
					dstpath1 = '"' + dstpath1[0] + '"'
				else: dstpath1 = ' '
				if not dstId1 in id_nodetype_map.keys():
					not_in_cnt += 1
					continue
				dstType1 = id_nodetype_map[dstId1]
				if dstType1 == 'MemoryObject' or dstType1 == 'UnnamedPipeObject' or dstType1 == 'unknown' or dstType1 == 'NetFlowObject':
					this_edge1 = str(timestamp) + ' ' + str(srcId) + ' ' + str(srcType) + ' ' + str(edgeType) + ' ' + str(dstId1) + ' ' + str(dstType1) + ' ' + str(dstpath1)  + '\n'
				else:
					this_edge1 = str(timestamp) + ' ' + str(srcId) + ' ' + str(srcType) + ' ' + str(edgeType) + ' ' + str(dstId1) + ' ' + str(dstType1)  + '\n'
				fw.write(this_edge1)

			dstId2 = pattern_dst2.findall(line)
			dstpath2 = pattern_dstpath2.findall(line)
			if len(dstId2) > 0  and dstId2[0] != 'null':
				dstId2 = dstId2[0]
				if len(dstpath2) > 0  and dstpath2[0] != 'null':
					dstpath2 = '"' + dstpath2[0] + '"'
				else: dstpath2 = ' '
				if not dstId2 in id_nodetype_map.keys():
					not_in_cnt += 1
					continue
				dstType2 = id_nodetype_map[dstId2]
				if dstType2 == 'MemoryObject' or dstType2 == 'UnnamedPipeObject' or dstType2 == 'unknown' or dstType2 == 'NetFlowObject':
					this_edge2 = str(timestamp) + ' ' + str(srcId) + ' ' + str(srcType) + ' ' + str(edgeType) + ' ' + str(dstId2) + ' ' + str(dstType2) + ' ' + str(dstpath2)  + '\n'
				else:
					this_edge2 = str(timestamp) + ' ' + str(srcId) + ' ' + str(srcType) + ' ' + str(edgeType) + ' ' + str(dstId2) + ' ' + str(dstType2)  + '\n'
				fw.write(this_edge2)	
	print(cnt)
	fw.close()
	f.close()