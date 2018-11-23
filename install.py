import sys
import os

def install():
	os.system("apt update")
	os.system("pip install mechanize json whois python-whois requests bs4 requests[socks] urlparse cookielib") 
	os.system("pip install scapy datetime argparse re threading urllib2 modules builtwith smtplib")
	os.system("apt install python-socks -y")
	os.system("apt install nmap -y")
	os.system("apt install php -y")
	os.system("apt install perl -y")
	print """entering big download region prepare you anus
	if your not ready press ctrl C or X out the terminal window"""
	os.system("sleep 5")
	os.system("apt install metasploit-framework -y")
	os.system("apt install setoolkit -y")
	os.system("apt install wifite -y")
	os.system("apt install reaver -y")
	os.system("apt install aircrack-ng -y")



print "are you running on the real kali linux os   [y/n]"
check = raw_input("[y/n]> ")
if check == "y" :
	print "ok most tools should work for you you might have to install other"
	print "things on your os for this to work if it doesnt work"
	os.system("sleep 2")
	install()

if check == "n" :
	print "then some of the tools in this script might not work"
	print "do you want to continue installation  [y/n]"
	install = raw_input("[y/n]> ")
	if install == "y" :
		def install():
			os.system("apt update")
			os.system("pip install mechanize json whois python-whois requests bs4 requests[socks] urlparse cookielib") 
			os.system("pip install scapy datetime argparse re threading urllib2 modules builtwith smtplib")
			os.system("apt install python-socks -y")
			os.system("apt install nmap -y")
			os.system("apt install php -y")
			os.system("apt install perl -y")
			print """entering big download region prepare you anus
			if your not ready press ctrl C or X out the terminal window"""
			os.system("sleep 5")
			os.system("apt install metasploit-framework -y")
			os.system("apt install setoolkit -y")
			os.system("apt install wifite -y")
			os.system("apt install reaver -y")
			os.system("apt install aircrack-ng -y")

		install()
	if install == "n" :
		print "thanks for checking out my script"
		sys.exit
