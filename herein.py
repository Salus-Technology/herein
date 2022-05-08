""" """

__author__ = "H. Kyle Wiseman"
__copyright__ = "Copyright 2021, Salus Technology"
__credits__ = ["H. Kyle Wiseman", "Jason M. Pittman"]
__license__ = "GPLv3"
__version__ = "0.6.0"
__maintainer__ = "H. Kyle Wiseman"
__email__ = "hkylewiseman@gmail.com"
__status__ = "Development"

from contextlib import nullcontext
import sys
import socket
import os
from scapy.all import *
import getpass
import configparser
from kommen_shared.remote_access_sequence import RemoteAccessCodeSequenceHandler
from kommen_shared.remote_access_code import RemoteAccessCodeHandler
from kommen_shared.asym_crypto import AsymmetricCryptographyHandler

class herein:
    def __init__(self):
        self.dest_addr = "127.0.0.1"
        self.dest_port = []
        self.count = -1
        self.message = "" # Raw(b"X"*1024)
        self.crypto = AsymmetricCryptographyHandler()
        self.client = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
        self.protocol = "tcp"
        self.rac = ''
        self.rac_handler = RemoteAccessCodeHandler(None, None)
        self.racs_handler = RemoteAccessCodeSequenceHandler()
        self.config = configparser.ConfigParser()
        self.dest_host = ''
        self.keyfile = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08_public.pem"
    def config_to_val(self):
        self.config.read("conf/hosts.ini")
        self.dest_addr = self.config[self.dest_host]['ip_addr']
        self.count = self.config[self.dest_host]['count']
        self.keyfile = self.config[self.dest_host]['keyfile']

    def make_tcp(self, d_port):
        try:
            ip = IP(dst=self.dest_addr)
            tcp = TCP(sport=RandShort(), dport=d_port, flags="S")
            packet = ip / tcp / self.message
            send(packet, loop=0, verbose=1)
            print("Sent packet to: " + self.dest_addr)

        except Exception as e:
            print("Failure sending tcp packet: " + str(e))

    def update_count(self):
        try:
            confFile = open("conf/hosts.ini", "w")
            update_count = int(self.count) + 1
            self.config.set(self.dest_host,'count', str(update_count))
            self.config.write(confFile)
            confFile.close()
        except Exception as e:
            print("Error updating OTP counter > " + str(e))
    # def return_clients(self):
    #     client_names = list()
    #     client_hashes = list()
    #     self.config.read("conf/hosts.ini")
    #     for entry in self.config:
    #         if(entry != "DEFAULT"):
    #             client_names.append(entry)
    #             client_hashes.append(self.config[entry]['name'])
    #     return (client_names, client_hashes)
    # def list_clients(self):
    #     client_names, client_hashes = self.return_clients()
    #     for name in client_names:
    #         print("Client: " + name)
    def preamble(self, host):
        self.dest_host = host
        self.message = '%s,%s,%s' % (self.client, self.count, self.keyfile)
        self.make_tcp(5002)

    # def register_client(self):
    #     client_names, client_hashes = self.return_clients()
    #     menu_opt = 0
    #     new_keys = list()
    #     keys = list()
    #     try:
    #         files = os.listdir("keys/")
    #         for key in files:
    #             if(key.endswith(".pem")):
    #                 keys.append(key)
    #         for key in keys:
    #             if not key in client_hashes:
    #                 new_keys.append(key)
    #         for key in new_keys:
    #             print(str(menu_opt) + ") " + key)
    #             menu_opt = menu_opt + 1
    #         menu_choice = input("Which key would you like to register (enter q to exit): ")
    #         if(menu_choice != "q"):
    #             new_host_name = input("Enter desired hostname for this client: ")
    #             new_ip_addr = input("Enter IP Address of client: ")
    #             self.write_to_config(new_host_name, new_keys[int(menu_choice)], new_ip_addr)
    #     except Exception as e:
    #         print("Error: " + str(e))

    # def write_to_config(self, hostname, keyfile, ip_address):
    #     try:
    #         print(keyfile)
    #         confFile = open("conf/hosts.ini", "a")
    #         confFile.write("[" + hostname + "]\n")
    #         confFile.write("name = " + os.path.splitext(keyfile)[0] + "\n")
    #         confFile.write("keyfile = " + keyfile + "\n")
    #         confFile.write("ip_addr = " + ip_address + "\n")
    #         confFile.write("count = 0 \n")
    #     except Exception as e:
    #         print("Error: " + str(e))
        
    def send_packet(self):
        self.config_to_val()
        client.generate_rac()
        client.generate_racs()
        client.update_count()
        sequenceCount = 1
        for port in self.dest_port:
            self.message = '%s, %s, %s' % (self.client, sequenceCount, port)
            print(self.message)
            self.make_tcp(port)
            sequenceCount = sequenceCount + 1
    
    def generate_rac(self):
        self.rac = self.rac_handler.generate_rac(int(self.count))

    def generate_racs(self):
        self.racs_handler.generate_racs(self.rac)
        self.racs_handler.verify_racs()
        self.dest_port = self.racs_handler.get_racs()
        print(self.dest_port)

if __name__ == "__main__":
    client = herein()
    try:
        client.preamble(sys.argv[1])

        client.send_packet()
    except Exception as e:
        print(e)
