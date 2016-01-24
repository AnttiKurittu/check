#coding=UTF-8

###### check.py ################################################################
#
# Depends on:
# GeoIP (pip install geoip)
# IPy (pip install IPy)
# requests (pip install requests)
# dnspython (https://github.com/rthalley/dnspython)
# passivetotal (https://github.com/passivetotal/passivetotal_tools/),
# install the python module from api_helpers
# required system commands: "whois" and "ping"
#
# Export your API keys as environmental variables;
# VTAPIKEY for VirusTotal API key, PTAPIKEY for PassiveTotal. If not present,
# those scans will be skipped.
# add "export VTAPIKEY=yourapikey" to your shell startup script yo export.
#
# if you get trouble email me at antti@kurittu.org and I'll try to help!
# Tested with debian and OS X, I have no idea whether this thing works on
# Windows.
#
# - Antti Kurittu (antti@kurittu.org)
#
###### check.py ################################################################

import os, sys, datetime, socket, urllib, urllib2, json, argparse, webbrowser, subprocess, zipfile, dns.resolver, requests, GeoIP, StringIO
from passivetotal import PassiveTotal
from IPy import IP

parser = argparse.ArgumentParser(description='Get actions')
parser.add_argument("-a", "--all", help="Run all queries", action="store_true")
parser.add_argument("-an", "--allnotnoisy", help="Run all queries that do not interact with the host directly", action="store_true")
parser.add_argument("-d", "--domain", metavar='domain name', type=str, help="Target domain name")
parser.add_argument("-i", "--ip", metavar='IP address', type=str, help="Target IP address")
parser.add_argument("-p", "--ping", help="Ping IP address", action="store_true")
parser.add_argument("-w", "--whois", help="Query WHOIS information", action="store_true")
parser.add_argument("-s", "--scan", help="Scan common ports", action="store_true")
parser.add_argument("-g", "--geoip", help="Query GeoIP database", action="store_true")
parser.add_argument("-sh", "--scanheaders", help="Scan common ports and try to retrieve HTTP headers", action="store_true")
parser.add_argument("-sp", "--spamlist", help="Check SURBL and SpamHaus blocklists for IP", action="store_true")
parser.add_argument("-ml", "--malwarelist", help="Check malware blocklists for address.", action="store_true")
parser.add_argument("-lo", "--listsonly", help="Only check malware blocklists, then quit. Use for inactive addresses.", action="store_true")
parser.add_argument("-pt", "--passivetotal", help="Query passive DNS records from PassiveTotal", action="store_true")
parser.add_argument("-vt", "--virustotal", help="Query passive DNS records from VirusTotal", action="store_true")
parser.add_argument("-o", "--open", help="Open GeoIP location in Google Maps", action="store_true")
parser.add_argument("-L", "--logfile", type=str, help="Specify log file, default is check-[IP]-[DATETIME].log")
parser.add_argument("-NL", "--nolog", help="Do not write log", action="store_true")
parser.add_argument("-M", "--monochrome", help="Do not use colored output or graphics", action="store_true")
parser.add_argument("-NG", "--nogfx", help="Do not use line graphics", action="store_true")
parser.add_argument("-S", "--nosplash", help="Suppress cool ASCII graphics", action="store_true")
commandlineArgument = parser.parse_args()

if not commandlineArgument.nosplash:
  print "       .__                   __                      "
  print "  ____ |  |__   ____   ____ |  | __    ______ ___.__."
  print "_/ ___\|  |  \_/ __ \_/ ___\|  |/ /    \____ <   |  |"
  print "\  \___|   Y  \  ___/\  \___|    <     |  |_> >___  |"
  print " \___  >___|  /\___  >\___  >__|_ \ /\ |   __// ____|"
  print "     \/     \/     \/     \/     \/ \/ |__|   \/     "
  print ""
  print "Simple address information aggregation tool. See -h for arguments and usage."
  print ""

if commandlineArgument.monochrome:
  class bcolors:
      HEADER = ''
      OKBLUE = ''
      OKGREEN = ''
      WARNING = ''
      FAIL = ''
      ENDC = ''
      BOLD = ''
      UNDERLINE = ''
else:
  class bcolors:
      HEADER = '\033[95m'
      OKBLUE = '\033[94m'
      OKGREEN = '\033[92m'
      WARNING = '\033[93m'
      FAIL = '\033[91m'
      ENDC = '\033[0m'
      BOLD = '\033[1m'
      UNDERLINE = '\033[4m'

if commandlineArgument.nogfx:
  class gfx:
      STAR = ''
      PLUS = ''
      PIPE = ''
      FAIL = ''
      MINUS = ''
else:
  class gfx:
      STAR = "[*] "
      PLUS = "[+] "
      PIPE = " |  "
      FAIL = "[!] "
      MINUS = "[-] "

## Specify resources and API keys

currentDateTime = str(datetime.datetime.now().strftime("%Y-%m-%d-%H:%M"))
GeoIPDatabaseFile = "/usr/local/share/GeoIP/GeoLiteCity.dat" # Specify database file location
targetPortscan = [20, 22, 23, 25, 53, 80, 8000, 8080, 8081, 8088, 6667, 6668, 123, 156, 443, 10000] # What ports to scan
sourceListURL = ['http://www.malware-domains.com/files/domains.zip', 'http://www.malwaredomainlist.com/mdlcsv.php', 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist', 'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist', 'https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset']
sourceListSpamDNS = ["zen.spamhaus.org", "spam.abuse.ch", "cbl.abuseat.org", "virbl.dnsbl.bit.nl", "dnsbl.inps.de",
"ix.dnsbl.manitu.net", "dnsbl.sorbs.net", "bl.spamcannibal.org", "bl.spamcop.net", "xbl.spamhaus.org", "pbl.spamhaus.org",
"dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net", "db.wpbl.info"] # What sources to query for malwarelists
try:
    VirusTotalAPIKey = os.environ['VTAPIKEY'] ### Export your api keys to shell variables or put them here, add "Export VTAPIKEY=yourapikey to .bashrc or whatever your using."
except KeyError:
    VirusTotalAPIKey = ""
    print gfx.FAIL + bcolors.FAIL + "Error: VirusTotal API key not present."
try:
    PassiveTotalAPIKey = os.environ['PTAPIKEY'] ### same here.
except KeyError:
    PassiveTotalAPIKey = ""
    print gfx.FAIL + bcolors.FAIL + "Error: PassiveTotal API key not present."

logfile = "" # Set variable as blank to avoid errors further on.

def validate_ip(s): # Validate IP address format
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

if commandlineArgument.ip and commandlineArgument.domain:
    print gfx.FAIL + bcolors.FAIL + "Specify an IP address or domain, not both! Exiting..."
    exit()
if commandlineArgument.ip:
  if validate_ip(commandlineArgument.ip) == False:
    print gfx.FAIL + bcolors.FAIL + "Invalid IP address, exiting..."
    exit()
  else:
   targetIPaddress = commandlineArgument.ip
   targetHostname = "Not defined"
elif commandlineArgument.domain:
  targetHostname = commandlineArgument.domain
  try:
    targetIPaddress = socket.gethostbyname(commandlineArgument.domain)
  except socket.gaierror:
    print bcolors.FAIL + bcolors.FAIL + "Resolve error, assignign 127.0.0.1 as ip"
    targetIPaddress = "127.0.0.1"
else:
  print gfx.FAIL + bcolors.FAIL + "No target given, exiting..."
  exit()

targetIPrange = targetIPaddress.split(".") # Split to get a range for rangematches in blacklists
targetIPrange = targetIPrange[0] + "." + targetIPrange[1] + "." + targetIPrange[2] + ".0"
print bcolors.HEADER + gfx.STAR + "Using IP address " + targetIPaddress + bcolors.ENDC

if not commandlineArgument.nolog:
  if commandlineArgument.logfile:
    logfile = commandlineArgument.logfile
  else:
    if commandlineArgument.domain:
        logfile = "check-" + targetHostname + "-"+ currentDateTime + ".log"
    else:
        logfile = "check-" + targetIPaddress + "-"+ currentDateTime + ".log"
  class Logger(object):
    def __init__(self, filename = logfile):
        self.terminal = sys.stdout
        self.log = open(filename, "w")
    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
    def flush(self):
        self.terminal.flush()

  sys.stdout = Logger(logfile)

else:
  print bcolors.WARNING + gfx.MINUS + "Skipping log file." + bcolors.ENDC

### MALWAREBLOCKLISTS

if commandlineArgument.malwarelist or commandlineArgument.all or commandlineArgument.allnotnoisy or commandlineArgument.listsonly:
  print bcolors.HEADER + gfx.STAR + "Checking malware blocklists for domain name and IP address." + bcolors.ENDC
  i = 0
  for sourceurl in sourceListURL:
      i += 1
      listfile = ""
      linecount = 0
      domainmatch = False
      ipmatch = False
      partial = targetHostname.split(".")
      sourcesCount = len(sourceListURL)
      print gfx.PLUS + "Downloading from %s [%s of %s sources]:" % (sourceurl, i, sourcesCount) + bcolors.ENDC
      try:
          data = ""
          req = requests.get(sourceurl, stream=True)
          filesize = req.headers.get('content-length')
          if not filesize:
              # Assuming no headers
              sys.stdout.write(gfx.FAIL + bcolors.FAIL + "No headers received, can't display progress." + bcolors.ENDC)
              data = req.content
              cType = "text/plain"
          else:
              cType = req.headers.get('content-type')
              sys.stdout.write(gfx.PLUS + "[          ] Filesize: " + str(int(filesize) / 1024) + " kb \tContent type: " + cType + " \r" + gfx.PLUS + "[")
              percent = int(filesize) / 10
              for chunk in req.iter_content(percent):
                  sys.stdout.write(bcolors.OKGREEN + "#" + bcolors.ENDC)
                  sys.stdout.flush()
                  data = data + chunk
          if "application/zip" in cType:
              zip_file_object = zipfile.ZipFile(StringIO.StringIO(data))
              first_file = zip_file_object.namelist()[0]
              file = zip_file_object.open(first_file)
              listfile = file.read()
          elif "text/plain" in cType or "application/csv" in cType:
              listfile = data
          else:
              print gfx.FAIL + bcolors.FAIL + "Unknown content type:", cType, ". Treating as plaintext."
              listfile = data
          for line in listfile.splitlines():
              linecount += 1
          print "\r\n" + gfx.PLUS + "Searching from %s lines." % (linecount) + bcolors.ENDC
          print gfx.PIPE
          for line in listfile.splitlines():
            if targetHostname in line:
              domainmatch = True
              print gfx.PIPE + bcolors.WARNING + "Matching domain: " + line + bcolors.ENDC
            if targetIPaddress in line:
              ipmatch = True
              print gfx.PIPE + bcolors.WARNING + "Matching IP: " + line + bcolors.ENDC
            if targetIPrange in line:
              ipmatch = True
              print gfx.PIPE + bcolors.WARNING + "IP in range: " + line + bcolors.ENDC

          if domainmatch == False and ipmatch == True:
            print gfx.PIPE + bcolors.OKGREEN + "Domain name not found." + bcolors.ENDC
          elif ipmatch == False and domainmatch == True:
            print gfx.PIPE + bcolors.OKGREEN + "IP address not found." + bcolors.ENDC
          else:
            print gfx.PIPE + bcolors.OKGREEN + "Domain name or IP address not found." + bcolors.ENDC

      except Exception:
          print gfx.FAIL + bcolors.FAIL + "Failed: ", str(sys.exc_info()[0]), str(sys.exc_info()[1])
      print gfx.PIPE

else:
  print bcolors.WARNING + gfx.MINUS + "Skipping malwarelists query, Enable with \"--malwarelist\" or \"-ml\"" + bcolors.ENDC

### SPAMLISTS

if commandlineArgument.spamlist or commandlineArgument.all or commandlineArgument.allnotnoisy or commandlineArgument.listsonly:
    print bcolors.HEADER + gfx.STAR + "Querying spamlists for %s..." % (targetIPaddress) + bcolors.ENDC
    print gfx.PIPE
    for bl in sourceListSpamDNS:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(targetIPaddress).split("."))) + "." + bl
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            print gfx.PIPE + bcolors.WARNING + 'IP: %s IS listed in %s (%s: %s)' %(targetIPaddress, bl, answers[0], answer_txt[0]) + bcolors.ENDC
        except dns.resolver.NXDOMAIN:
            print gfx.PIPE + 'IP: %s is NOT listed in %s' %(targetIPaddress, bl)
    print gfx.PIPE
else:
  print bcolors.WARNING + gfx.MINUS + "Skipping spam blocklists check, Enable with \"--spamlists\" or \"-sp\"" + bcolors.ENDC

if commandlineArgument.listsonly:
  print bcolors.HEADER + gfx.STAR + "Ran with --listsonly, done."
  exit()

## SEE IF IP IS LIVE

if targetIPaddress != "127.0.0.1":
    iptype = IP(targetIPaddress).iptype()
else:
    iptype="PUBLIC"
if iptype == "PRIVATE" or iptype == "LOOPBACK":
  print bcolors.FAIL + gfx.STAR + "IP address type is \'" + iptype.lower() + "\', can not process. Exiting..."
  exit()
else:
  print bcolors.HEADER + gfx.STAR + "Fully Qualified Doman Name: " + socket.getfqdn(targetIPaddress) + bcolors.ENDC

#### PING

if commandlineArgument.ping or commandlineArgument.all:
  print bcolors.HEADER + gfx.PLUS + "Pinging target, skip with CTRL-C..." + bcolors.ENDC
  print gfx.PIPE + bcolors.ENDC
  try:
    response = os.system("ping -c 1 " + targetIPaddress + " > /dev/null 2>&1")
    if response == 0:
      print gfx.PIPE + bcolors.OKGREEN + targetIPaddress, 'is responding to ping.' + bcolors.ENDC
    else:
      print gfx.PIPE + bcolors.FAIL + targetIPaddress, 'is not responding to ping.' + bcolors.ENDC
    print gfx.PIPE + bcolors.ENDC
  except KeyboardInterrupt:
    print bcolors.WARNING + gfx.MINUS + "Skipping ping." + bcolors.ENDC
else:
  print bcolors.WARNING + gfx.MINUS + "Skipping ping, Enable pinging with \"--ping\" or \"-P\"" + bcolors.ENDC

### WHOIS

if commandlineArgument.whois or commandlineArgument.all or commandlineArgument.allnotnoisy:
  results = results2 = ""
  try:
    results = subprocess.check_output("whois "+targetIPaddress, shell=True)
  except subprocess.CalledProcessError:
    gfx.FAIL + bcolors.FAIL + "Whois returned an error."
  if targetHostname != "Not defined":
    try:
      results2 = subprocess.check_output("whois "+targetHostname, shell=True)
    except subprocess.CalledProcessError:
      gfx.FAIL + bcolors.FAIL + "Whois returned an error."
  if results:
    print bcolors.HEADER + gfx.STAR + "Querying IP Address " + targetIPaddress + bcolors.ENDC
    for line in results.splitlines():
      if "#" in line:
        ()
      elif ("abuse" in line and "@" in line) or "address" in line or "person" in line or "phone" in line:
        print gfx.PIPE + bcolors.BOLD + bcolors.OKBLUE + line + bcolors.ENDC
      elif "descr" in line:
        print gfx.PIPE + bcolors.BOLD + bcolors.WARNING + line + bcolors.ENDC
      else:
        print gfx.PIPE + line  + bcolors.ENDC
  if results2:
    print bcolors.HEADER +  gfx.PLUS + "Resolved address " + targetIPaddress + " for domain " + targetHostname + bcolors.ENDC
    for line in results2.splitlines():
      if "#" in line:
        ()
      elif ("abuse" in line and "@" in line) or "address" in line or "person" in line or "phone" in line:
        print gfx.PIPE + bcolors.BOLD + bcolors.OKBLUE + line + bcolors.ENDC
      elif "descr" in line:
        print gfx.PIPE + bcolors.BOLD + bcolors.WARNING + line + bcolors.ENDC
      else:
        print gfx.PIPE + line  + bcolors.ENDC
else:
  print bcolors.WARNING + gfx.MINUS + "Skipping Whois. Enable with argument \"--whois\" or \"-w\""

### GEOIP

if commandlineArgument.geoip or commandlineArgument.all or commandlineArgument.allnotnoisy:
    latitude = ""
    longitude = latitude
    try:
        gi = GeoIP.open(GeoIPDatabaseFile, GeoIP.GEOIP_STANDARD)
        gir = gi.record_by_addr(targetIPaddress)
    except Exception:
        print gfx.FAIL + bcolors.FAIL + "Please install GeoIP database. http://dev.maxmind.com/geoip/legacy/install/city/"
        exit()
    print bcolors.HEADER + gfx.PLUS + "Querying GeoIP City database for " + targetIPaddress + "..." + bcolors.ENDC
    if gir is None:
     print "[!] "+ bcolors.FAIL + "No geodata."
    else:
      print gfx.PIPE + bcolors.ENDC
      for key, value in gir.iteritems():
        if key == "latitude":
          latitude = value
        elif key == "longitude":
          longitude = value
        print gfx.PIPE + str(key) + ": " + str(value)
      if latitude != "" and longitude != "":
        print gfx.PIPE + "Google maps link for location: " + bcolors.UNDERLINE + "https://maps.google.com/maps?q="+str(latitude)+","+str(longitude) + bcolors.ENDC
        print gfx.PIPE + bcolors.ENDC
        if commandlineArgument.open:
          webbrowser.open('https://maps.google.com/maps?q='+str(latitude)+','+str(longitude))
else:
    print bcolors.WARNING + gfx.MINUS + "Skipping GeoIP. Enable with argument \"--geoip\" or \"-g\""

### VIRUSTOTAL

if (commandlineArgument.virustotal or commandlineArgument.all or commandlineArgument.allnotnoisy) and VirusTotalAPIKey != "":
  print bcolors.HEADER + gfx.PLUS + "Querying VirusTotal for " + targetIPaddress + "..." + bcolors.ENDC
  vturl = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
  parameters = {'ip': targetIPaddress, 'apikey': VirusTotalAPIKey}
  vtresponse = urllib.urlopen('%s?%s' % (vturl, urllib.urlencode(parameters))).read()
  vtresponse_dict = json.loads(vtresponse)
  if vtresponse_dict['response_code'] == 0:
    print bcolors.WARNING + gfx.STAR + "VirusTotal response: IP address not in dataset." + bcolors.ENDC
  else:
    print bcolors.OKGREEN + gfx.PLUS + "VirusTotal response code", vtresponse_dict['response_code'], vtresponse_dict['verbose_msg'] + bcolors.ENDC
    print gfx.PIPE
    for entry in vtresponse_dict['resolutions']:
      print gfx.PIPE + "Hostname:", entry['hostname'], "Last resolved:", entry['last_resolved']
    print gfx.PIPE
    print bcolors.OKGREEN + gfx.PLUS + "Detections in this address:" + bcolors.ENDC
    print gfx.PIPE
    for entry in vtresponse_dict['detected_urls']:
      print gfx.PIPE + entry['url'].replace("http", "hxxp") + bcolors.ENDC
      if entry['positives'] >= 1:
        print gfx.PIPE + "Positives: ", bcolors.FAIL + str(entry['positives']) + bcolors.ENDC, "\tTotal:", entry['total'], "\tScan date:", entry['scan_date']
      else:
        print gfx.PIPE + "Positives: ", entry['positives'], "\tTotal:", entry['total'], "\tScan date:", entry['scan_date']
    print gfx.PIPE
else:
  print bcolors.WARNING + gfx.MINUS + "Skipping VirusTotal passive DNS, Enable with \"--virustotal\" or \"-vt\"" + bcolors.ENDC

### PASSIVETOTAL

if (commandlineArgument.passivetotal or commandlineArgument.all or commandlineArgument.allnotnoisy) and PassiveTotalAPIKey != "":
  #disable passivetotal's error message
  requests.packages.urllib3.disable_warnings()
  #define API key
  pt = PassiveTotal(PassiveTotalAPIKey)
  print bcolors.HEADER + gfx.PLUS + "Querying PassiveTotal for " + targetIPaddress + "..." + bcolors.ENDC
  print gfx.PIPE + bcolors.ENDC
  response = pt.get_passive(targetIPaddress)
  if response['success']:
    print gfx.PIPE + "Query:", response['raw_query']
    print gfx.PIPE + "First Seen:", response['results']['first_seen']
    print gfx.PIPE + "Last Seen:", response['results']['last_seen']
    print gfx.PIPE + "Resolve Count: ", response['result_count']
    print gfx.PIPE + "Resolutions"
    response = response['results']
    for resolve in response['records']:
      print gfx.PIPE + "==> ", resolve['resolve'], "\t", resolve['firstSeen'], "\t", resolve['lastSeen'], "\t", ', '.join([ str(x) for x in resolve['source'] ])
  else:
    print bcolors.FAIL + "[!] Error when getting passive for %s: %s" % (targetIPaddress, response['error']) + bcolors.ENDC
  print gfx.PIPE + bcolors.ENDC
else:
  print bcolors.WARNING + gfx.MINUS + "Skipping PassiveTotal. Enable with argument \"--passive\" or \"-p\"" + bcolors.ENDC

### SCANPORTS

if commandlineArgument.scan or commandlineArgument.all:
    print bcolors.HEADER + gfx.PLUS + "Scanning common ports..." + bcolors.ENDC
    print gfx.PIPE + bcolors.ENDC
    socket.setdefaulttimeout(1)
    try:
      for port in targetPortscan:
        if commandlineArgument.scanheaders:
            print gfx.PIPE + "Scanning port " + str(port) + " and attempting to get headers..." + bcolors.ENDC
        else:
            print gfx.PIPE + "Scanning port " + str(port) + "..." + bcolors.ENDC
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((targetIPaddress, port))
        if result == 0:
          print gfx.PIPE + bcolors.OKGREEN + "port " + str(port) + " is open." + bcolors.ENDC
          if commandlineArgument.scanheaders and targetHostname != "Not defined":
            url = "http://" + targetHostname
            try:
              print bcolors.HEADER + gfx.PLUS + "Trying to retrieve http://" + targetHostname + " from port " + str(port) + bcolors.ENDC
              page = urllib2.urlopen('http://' + targetHostname)
              print bcolors.HEADER + gfx.PLUS + "Getting headers..."+bcolors.ENDC
              for line in str(page.info()).splitlines():
                  print bcolors.BOLD + gfx.PIPE + line + bcolors.ENDC
            except Exception,e:
              print bcolors.FAIL + "[!] " + str(e) + bcolors.ENDC
        sock.close()
    except KeyboardInterrupt:
      print bcolors.FAIL + gfx.STAR + "Caught Ctrl+C, interrupting..."
      sys.exit()
    except socket.gaierror:
      print bcolors.FAIL + gfx.STAR + "Hostname could not be resolved. Exiting..."
      sys.exit()
    except socket.error:
      print bcolors.FAIL + gfx.STAR + "Couldn't connect to server."
      sys.exit()
    print gfx.PIPE + bcolors.ENDC
else:
    print bcolors.WARNING + gfx.MINUS + "Skipping portscan. Enable scanning with argument \"--scan\" or \"-s\""
if logfile != "":
  print bcolors.HEADER + gfx.STAR + "Writing log file to " + logfile + bcolors.ENDC

print bcolors.HEADER + gfx.STAR + "Done." + bcolors.ENDC
exit()
