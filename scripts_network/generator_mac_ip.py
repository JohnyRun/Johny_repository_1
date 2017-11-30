#!/usr/bin/python
# coding: utf8

import sys
from scapy.all import *


def generate_random_mac_ip(iface,count):
	'''
	Функция генерит пакеты со случайными mac/ip-адресами
	iface - интерфейс, куда необходимо отправлять пакеты
	count - число пакетов
	'''
	for i in range(1,count):
		sendp(Ether(src=RandMAC('*:*:*:*:*:*') ,dst=RandMAC('*:*:*:*:*:*'))/IP(src=RandIP('*.*.*.*'),dst=RandIP('*.*.*.*')),iface=iface,verbose=False,count=count)


if __name__ == "__main__":
	try:
		interface = sys.argv[1]
		count = int(sys.argv[2])
		generate_random_mac_ip(interface,count)
	except IndexError:	
		print('*'*25)
		print('DEFAULT VALUES:\niface="enp3s0",count=10')
		print('*'*25)
		print('Введите аргументы через пробел: iface,count_packets')
		interface='enp3s0'
		count = 10
		generate_random_mac_ip(interface,count)		