'''
# Group-#8
# Names: Hemant Kumar Sampath Kumar | Vasudharini Madhusudhanan | Manisha Savale
# This is an REST application that is going to be integrated with the Floodlight application 
# Application aims in providing the DDoS Detection and Mitigation Techniques and this is tested using 
OpenvSwitch and Floodlight Controller
#For More Details please refer to the Project report'''

# REST API calls can be made using this requests library
import requests
import logging
import datetime
# json library is handy in handling the data retrieved 
import json
from time import time


import subprocess
import paramiko
import sys
import time
import os
import re

class RateLimiter:
    def _init_(self,):
        print('Getting Ready for ssh')
        self.nbytes = 4096
        self.hostname = '10.0.0.17'
        self.host= '10.0.0.17'
        self.port = 22
        self.username = 'mininet' 
        self.password = 'mininet'
        #command = ['cd /shared','ls','sh /shared/config.sh']
    
	
    def get_connection(self,):
        print('Getting Ready for get_connection')
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=self.hostname, username=self.username, password=self.password, port=self.port)
        return client
        
    def get_channel(self,client):
        channel = client.get_transport().open_session()
        return channel

		
    def ssh_setup(self,client):	
        channel=self.get_channel(client)	
        channel.exec_command('sudo ovs-ofctl -O OpenFlow13 add-meter s1 meter=5,pktps,band=type=drop,rate=5')
        channel.close()
    def close_connection(self,client):	
        client.close()
    
   #test_object=Test()
   #test_object.runRegression()


#Let us have a base URL 
controller_base_url="http://10.0.0.231:8080/wm/"

#import json
i=0

while(True):
    #print 'hello'
    Controller_Device_Summary = controller_base_url + "core/controller/summary/json"
    
    Fetch_Flows= controller_base_url + "core/switch/all/flow/json"
    
    i=i+1
    
    GET_Device_Summary = requests.get(Fetch_Flows)
    
    #Let us set a threshold for the rate of packets entering the switch that helps in determining DDoS based attacks
    Threshold_PKTCT=0
    
    for i in range(1,len(GET_Device_Summary.json().keys())+1): # no of switches
        
        flows_per_switch=len(GET_Device_Summary.json()['00:00:00:00:00:00:00:0'+str(i)]['flows']) # no of flows per switch
       
        for flow in range (flows_per_switch): #flows per switch
           
            duration=GET_Device_Summary.json()['00:00:00:00:00:00:00:0'+str(i)]['flows'][flow]['durationSeconds']
    
            packet_count=GET_Device_Summary.json()['00:00:00:00:00:00:00:0'+str(i)]['flows'][flow]['packetCount']
    
            print 'duration',duration
    
            if not int(duration)==0:
    
                Threshold_PKTCT= float(packet_count)/float(duration) #no of packets per second
    
                print Threshold_PKTCT  			
    
                log_dict = datetime.datetime.now()
    
                print log_dict
    
            match_field = GET_Device_Summary.json()['00:00:00:00:00:00:00:0'+str(i)]['flows'][flow]['match']
            #print match_field
            if Threshold_PKTCT > 0 and not match_field =='{}':			
    
                #log_dict = datetime.datetime.now()
                t = time()
                print t
                #print log_dict
                
                IPV4_src = GET_Device_Summary.json()['00:00:00:00:00:00:00:0'+str(i)]['flows'][flow]['match']['ipv4_src']
                ip_log_dict = {}
                #ip_log_dict[IPV4_src] = t
                print IPV4_src
                print requests.post(controller_base_url+"/acl/rules/json",'{"src-ip":'+IPV4_src+'/32'+",action:deny}").json()
                print "*********" + str(ip_log_dict)
                obj=RateLimiter()
                client=obj.get_connection()
                obj.get_channel(client)   
                obj.ssh_setup(client)
                obj.close_connection(client)
                del obj
                print "Success"
     	        #duration=GET_Device_Summary.json()['00:00:00:00:00:00:00:0'+str(i)]['flows'][flow]['durationSeconds']
    
        	    #packet_count=GET_Device_Summary.json()['00:00:00:00:00:00:00:0'+str(i)]['flows'][flow]['packetCount']
	
    