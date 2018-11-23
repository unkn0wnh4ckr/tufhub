import os
import sys

print """
after uninstalling you still have
to delete the tufhub directory by
using the 'rm -fr tufhub' command
"""
os.system("sleep 2.5")
print "removing tufhub from bin"
os.system("rm /bin/tufhub")
print "removing all files in tufhub directory"
os.system("rm /root/tufhub *")
print """
now all you gotta do is open
the /root/.bashrc file in some
editor and delete the "export PATH=/bin/tufhub:$PATH"
line

print "do you know how to get their? [y/n]"
x = raw_input("[?]> ")
if x == "n" :
	print "what editor do you use [vim/nano]"
	f = raw_input("[EDIT]> ")
	if f == "nano" :
		print "ok il take you their"
		os.system("sleep 1")
		os.system("nano /root/.bashrc")
	if f == "vim" :
		print "ok il take you their"
		os.system("sleep 1")
		os.system("vim /root/.bashrc")
if x == "y" :
	print "follow \033[91m@unkn0wn_bali\033[0m on instagram"
	os.system("sleep 1")
	sys.exit()