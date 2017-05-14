#!/usr/bin/python
# -*- coding: utf-8 -*-
""" 
	MYSSniffer 	Dirk Clemens (iot@adcore.de)

    Usage: 		python tcp port
    Example: 	python 192.168.2.44 -p 5003

	history:
	1.0			2017-04-21		1st rough basic version (read/parse messages only)	

"""

import socket
import sys
import datetime

TCP_RECV_BUFFER_SIZE = 1024 

# https://www.mysensors.org/download/serial_api_20#message-structure
# node-id ; child-sensor-id ; command ; ack ; type ; payload \n
# The maximum payload size is 25 bytes!

mysCommandCodes = ['C_PRESENTATION', 'C_SET', 'C_REQ', 'C_INTERNAL', 'C_STREAM']
mysCommands = ['presentation', 'set', 'req', 'internal', 'stream']

mysPresenationCodes = ['S_DOOR','S_MOTION','S_SMOKE','S_BINARY','S_DIMMER','S_COVER','S_TEMP','S_HUM','S_BARO','S_WIND','S_RAIN','S_UV','S_WEIGHT','S_POWER','S_HEATER','S_DISTANCE','S_LIGHT_LEVEL','S_ARDUINO_NODE','S_ARDUINO_REPEATER_NODE','S_LOCK','S_IR','S_WATER','S_AIR_QUALITY','S_CUSTOM','S_DUST','S_SCENE_CONTROLLER','S_RGB_LIGHT','S_RGBW_LIGHT','S_COLOR_SENSOR','S_HVAC','S_MULTIMETER','S_SPRINKLER','S_WATER_LEAK','S_SOUND','S_VIBRATION','S_MOISTURE','S_INFO','S_GAS','S_GPS','S_WATER_QUALITY']
mysPresenationTypes = ['door','motion','smoke','binary','dimmer','cover','temp','hum','baro','wind','rain','uv','weight','power','heater','distance','light_level','arduino_node','arduino_repeater_node','lock','ir','water','air_quality','custom','dust','scene_controller','rgb_light','rgbw_light','color_sensor','hvac','multimeter','sprinkler','water_leak','sound','vibration','moisture','info','gas','gps','water_quality']

mysSetReqCodes = ['V_TEMP','V_HUM','V_STATUS','V_PERCENTAGE','V_PRESSURE','V_FORECAST','V_RAIN','V_RAINRATE','V_WIND','V_GUST','V_DIRECTION','V_UV','V_WEIGHT','V_DISTANCE','V_IMPEDANCE','V_ARMED','V_TRIPPED','V_WATT','V_KWH','V_SCENE_ON','V_SCENE_OFF','V_HVAC_FLOW_STATE','V_HVAC_SPEED','V_LIGHT_LEVEL','V_VAR1','V_VAR2','V_VAR3','V_VAR4','V_VAR5','V_UP','V_DOWN','V_STOP','V_IR_SEND','V_IR_RECEIVE','V_FLOW','V_VOLUME','V_LOCK_STATUS ','V_LEVEL','V_VOLTAGE','V_CURRENT','V_RGB','V_RGBW','V_ID','V_UNIT_PREFIX','V_HVAC_SETPOINT_COOL ','V_HVAC_SETPOINT_HEAT','V_HVAC_FLOW_MODE','V_TEXT','V_CUSTOM','V_POSITION','V_IR_RECORD','V_PH ','V_ORP','V_EC','V_VAR','V_VA','V_POWER_FACTOR']
mysSetReqTypes = ['temp','hum','status','percentage','pressure','forecast','rain','rainrate','wind','gust','direction','uv','weight','distance','impedance','armed','tripped','watt','kwh','scene_on','scene_off','hvac_flow_state','hvac_speed','light_level','var1','var2','var3','var4','var5','up','down','stop','ir_send','ir_receive','flow','volume','lock_status','level','voltage','current','rgb','rgbw','id','unit_prefix','hvac_setpoint_cool','hvac_setpoint_heat','hvac_flow_mode','text','custom','position','ir_record','ph','orp','ec','var','va','power_factor']
mysSetReqUnits = ['°C','%',' ','%','mB','forecast','rain','rainrate','wind','gust','°',' ','kg','m','ohm',' ',' ','W','kwh',' ',' ',' ',' ','lux',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','m','m³','  ',' ','V','A',' ',' ',' ',' ','  ',' ',' ',' ',' ',' ',' ','ph ','mV','μS/cm','var','va',' ']

mysInternalCodes = ['I_BATTERY_LEVEL','I_TIME','I_VERSION','I_ID_REQUEST','I_ID_RESPONSE','I_INCLUSION_MODE','I_CONFIG','I_FIND_PARENT','I_FIND_PARENT_RESPONSE','I_LOG_MESSAGE','I_CHILDREN','I_SKETCH_NAME','I_SKETCH_VERSION','I_REBOOT','I_GATEWAY_READY','I_REQUEST_SIGNING','I_GET_NONCE','I_GET_NONCE_RESPONSE','I_HEARTBEAT','I_PRESENTATION','I_DISCOVER','I_DISCOVER_RESPONSE','I_HEARTBEAT_RESPONSE','I_LOCKED ','I_PING','I_PONG','I_REGISTRATION_REQUEST','I_REGISTRATION_RESPONSE','I_DEBUG']
mysInternalTypes = ['battery_level','time','version','id_request','id_response','inclusion_mode','config','find_parent','find_parent_response','log_message','children','sketch_name','sketch_version','reboot','gateway_ready','request_signing','get_nonce','get_nonce_response','heartbeat','presentation','discover','discover_response','heartbeat_response','locked ','ping','pong','registration_request','registration_response','debug']

mysStreamCodes 	= ['ST_FIRMWARE_CONFIG_REQUEST','ST_FIRMWARE_CONFIG_RESPONSE','ST_FIRMWARE_REQUEST','ST_FIRMWARE_RESPONSE']
mysStreamTypes	= ['firmware_config_request','firmware_config_response','firmware_request','firmware_response','sound','image']

def parseMyMessage(message):
	# cut the '\n' at the end of each line
	message = message.strip('\n')
	parts 		= message.split(";") 
	mynodeid 	= int(parts[0])
	mychildid 	= int(parts[1])
	mycommand 	= int(parts[2])
	myack 		= int(parts[3])
	mytype 		= int(parts[4])
	mypayload	= parts[5]

	cmdTypes = 'n/a'
	unit = ''
	if (mycommand == 0): # presentation
		cmdTypes = mysPresenationTypes[mytype]
		cmdCodes = mysPresenationCodes[mytype]
	if ((mycommand == 1) or (mycommand == 2)): # set/req
		cmdTypes = mysSetReqTypes[mytype]	
		cmdCodes = mysSetReqCodes[mytype]	
		unit = mysSetReqUnits[mytype]
	if (mycommand == 3): # internal
		cmdTypes = mysInternalTypes[mytype]
		cmdCodes = mysInternalCodes[mytype]
	if (mycommand == 4): # stream 
		cmdTypes = mysStreamTypes[mytype]
		cmdCodes = mysStreamCodes[mytype]

	now = datetime.datetime.now()
	# timestr = unicode(now.replace(microsecond=0)).strftime("%Y-%m-%d %H:%M:%S")
	timestr = now.strftime("%Y-%m-%d %H:%M:%S")
	# print '%s: node[%3d] child[%3d] ack:%d %-15s %-25s | %s %s' % (timestr, mynodeid, mychildid, myack, mysCommands[mycommand], cmdTypes, mypayload, unit)
	print '%s: node[%3d] child[%3d] ack:%d %-15s %-25s | %s %s' % (timestr, mynodeid, mychildid, myack, mysCommandCodes[mycommand], cmdCodes, mypayload, unit)



def main():
	import argparse

	parser = argparse.ArgumentParser(description='Read and parse messages from MySensors Gateway.')
	parser.add_argument("-p", "--port", type=int, default=5003, help='port [default: 5003].')
	parser.add_argument("gateway", default="192.168.2.44", help='Ip address of the gateway.')
	args = parser.parse_args()

	# server_address = (args.gateway, args.port)
	print "connecting to %s port %s" % (args.gateway, args.port)

	# Create a TCP/IP socket
	try:
		#create an AF_INET, STREAM socket (TCP)
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error, msg:
		print 'Failed to create socket. Error code: ' + str(msg[0]) + ' , Error message : ' + msg[1]
		sys.exit();

	try:
		# remote_ip = socket.gethostbyname( host )
		sock = socket.create_connection((args.gateway, args.port)) 
	except socket.error, msg:
		print 'Failed to connect to socket. Error code: ' + str(msg[0]) + ' , Error message : ' + msg[1]
		sys.exit()

	try:    
		# # Send data
		# sock.sendall(message)
		while (True):
			pass
			#Now receive data
			data = sock.recv(TCP_RECV_BUFFER_SIZE)
			parseMyMessage(data)
	except KeyboardInterrupt:
		print 'closing socket'
		sock.close()
	finally:
		print 'closing socket'
		sock.close()
	sys.exit(0)	


if __name__ == "__main__":		
	main()
