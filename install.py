import sys
import os

def install():
	os.system("apt update")
	os.system("pip install mechanize json whois python-whois requests bs4 requests[socks] urlparse cookielib") 
	os.system("pip install scapy datetime argparse re threading urllib2 modules builtwith")
	os.system("apt install python-socks")
	os.system("apt install metasploit-framework")
	os.system("apt install setoolkit")
	os.system("apt install wifite")
	os.system("apt install reaver")
	os.system("apt install aircrack-ng")
	os.system("apt install nmap")
	os.system("apt install php")
	os.system("apt install perl")


os.system('''
#!/bin/bash
#Author: github.com/thelinuxchoice
#Instagram: @thelinuxchoice
trap 'echo exiting cleanly...; exit 1;' SIGINT SIGTSTP

checkroot() {

if [[ "$(id -u)" -ne 0 ]]; then
   printf "\e[1;77mPlease, run this program as root!\n\e[0m"
   exit 1
fi

}

checkroot

(trap '' SIGINT SIGTSTP && command -v tor > /dev/null 2>&1 || { printf >&2  "\e[1;92mInstalling TOR, please wait...\n\e[0m"; apt-get update > /dev/null && apt-get -y install tor > /dev/null || printf "\e[1;91mTor Not installed.\n\e[0m"; }) & wait $!

(trap '' SIGINT SIGTSTP && command -v curl > /dev/null 2>&1 || { printf >&2  "\e[1;92mInstalling cURL, please wait...\n\e[0m"; apt-get update > /dev/null && apt-get -y install curl > /dev/null || printf "\e[1;91mCurl Not installed.\n\e[0m"; }) & wait $!

printf "\e[1;92mAll Requires are installed!\n\e[0m"
''')


print "are you running on the real kali linux os   [y/n]"
check = raw_input("[y/n]> ")
if check == "y" :
	print "good"
	os.system("sleep 2")
	install()
if check == "n" :
	print "then a decent amount of tools in this script might not work"
	print "do you want to continue installation  [y/n]"
	install = raw_input("[y/n]> ")
	if install == "y" :
		install()
	if install == "n" :
		print "thanks for checking out my script"
		sys.exit
