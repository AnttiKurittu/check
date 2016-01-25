#coding=UTF-8

# See https://github.com/AnttiKurittu/check/ for details.

import os, sys, datetime, socket, urllib, urllib2, json, argparse, webbrowser, subprocess, zipfile, dns.resolver, requests, GeoIP, StringIO
from passivetotal import PassiveTotal
from IPy import IP

parser = argparse.ArgumentParser(description='Get actions')
parser.add_argument("-d", "--domain", metavar='domain name', type=str, help="Target domain name")
parser.add_argument("-i", "--ip", metavar='IP address', type=str, help="Target IP address")
parser.add_argument("-a", "--all", help="Run all queries", action="store_true")
parser.add_argument("-l", "--lists", help="Run all third-party queries (malwarelists, spamlists, virustotal, passivetotal, whois, geoip)", action="store_true")
parser.add_argument("-p", "--probes", help="Run all host-contacting probes (ping, scan ports, scan headers)", action="store_true")
parser.add_argument("-pg", "--ping", help="Ping IP address", action="store_true")
parser.add_argument("-ws", "--whois", help="Query WHOIS information", action="store_true")
parser.add_argument("-sp", "--scanports", help="Scan common ports", action="store_true")
parser.add_argument("-gi", "--geoip", help="Query GeoIP database", action="store_true")
parser.add_argument("-sh", "--scanheaders", help="Scan common ports and try to retrieve HTTP headers", action="store_true")
parser.add_argument("-sl", "--spamlists", help="Check SURBL and SpamHaus blocklists for IP", action="store_true")
parser.add_argument("-ml", "--malwarelists", help="Check malware lists for target", action="store_true")
parser.add_argument("-pt", "--passivetotal", help="Query passive DNS records from PassiveTotal", action="store_true")
parser.add_argument("-vt", "--virustotal", help="Query passive DNS records from VirusTotal", action="store_true")
parser.add_argument("-O", "--openlink", help="Open GeoIP location in Google Maps", action="store_true")
parser.add_argument("-L", "--logfile", type=str, help="Specify log file, default is log/check-[IP]-[DATETIME].log")
parser.add_argument("-NL", "--nolog", help="Do not write log", action="store_true")
parser.add_argument("-M", "--monochrome", help="Suppress colors", action="store_true")
parser.add_argument("-NG", "--nogfx", help="Suppress line graphics", action="store_true")
parser.add_argument("-S", "--nosplash", help="Suppress cool ASCII header graphic", action="store_true")
cliArg = parser.parse_args()

if not cliArg.nosplash:
  print "       .__                   __                      "
  print "  ____ |  |__   ____   ____ |  | __    ______ ___.__."
  print "_/ ___\|  |  \_/ __ \_/ ___\|  |/ /    \____ <   |  |"
  print "\  \___|   Y  \  ___/\  \___|    <     |  |_> >___  |"
  print " \___  >___|  /\___  >\___  >__|_ \ /\ |   __// ____|"
  print "     \/     \/     \/     \/     \/ \/ |__|   \/     "
  print ""
  print "Simple address information aggregation tool. See -h for arguments and usage."
  print ""

if cliArg.monochrome:
  class clr:
      HDR = ''
      B = ''
      G = ''
      Y = ''
      R = ''
      END = ''
      BOLD = ''
      UL = ''
else:
  class clr:
      HDR = '\033[95m'
      B = '\033[94m'
      G = '\033[92m'
      Y = '\033[93m'
      R = '\033[91m'
      END = '\033[0m'
      BOLD = '\033[1m'
      UL = '\033[4m'

if cliArg.nogfx:
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
malwareSourceFile = "malwaresources.txt"
#sourceListURL = ['http://www.malware-domains.com/files/domains.zip', 'http://www.malwaredomainlist.com/mdlcsv.php', 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist', 'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist', 'https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset']
sourceListSpamDNS = ["zen.spamhaus.org", "spam.abuse.ch", "cbl.abuseat.org", "virbl.dnsbl.bit.nl", "dnsbl.inps.de",
"ix.dnsbl.manitu.net", "dnsbl.sorbs.net", "bl.spamcannibal.org", "bl.spamcop.net", "xbl.spamhaus.org", "pbl.spamhaus.org",
"dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net", "db.wpbl.info"] # What sources to query for malwarelists
logfile = "" # Set variable as blank to avoid errors further on.
runerrors = False

try:
    VirusTotalAPIKey = os.environ['VTAPIKEY'] ### Export your api keys to shell variables or put them here, add "Export VTAPIKEY=yourapikey to .bashrc or whatever your using."
except KeyError:
    VirusTotalAPIKey = ""
    print gfx.FAIL + clr.R + "Error: VirusTotal API key not present. Add \"$ export VTAPIKEY=yourapikey\" to your startup script." + clr.END
try:
    PassiveTotalAPIKey = os.environ['PTAPIKEY'] ### same here.
except KeyError:
    PassiveTotalAPIKey = ""
    print gfx.FAIL + clr.R + "Error: PassiveTotal API key not present. Add \"$ export PTAPIKEY=yourapikey\" to your startup script." + clr.END

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

if cliArg.ip and cliArg.domain:
    print gfx.FAIL + clr.R + "Specify an IP address or domain, not both! Exiting..."
    runerrors = True
    exit()
if cliArg.ip:
  if validate_ip(cliArg.ip) == False:
    print gfx.FAIL + clr.R + "Invalid IP address, exiting..."
    runerrors = True
    exit()
  else:
   targetIPaddress = cliArg.ip
   targetHostname = "Not defined"
elif cliArg.domain:
  targetHostname = cliArg.domain
  try:
    targetIPaddress = socket.gethostbyname(cliArg.domain)
  except socket.gaierror:
    print clr.R + clr.R + "Resolve error, assignign 127.0.0.1 as ip"
    targetIPaddress = "127.0.0.1"
else:
  print gfx.FAIL + clr.R + "No target given, exiting..."
  runerrors = True
  exit()

targetIPrange = targetIPaddress.split(".") # Split to get a range for rangematches in blacklists
targetIPrange = targetIPrange[0] + "." + targetIPrange[1] + "." + targetIPrange[2] + ".0"
print clr.HDR + gfx.STAR + "Using IP address " + targetIPaddress + clr.END

if not cliArg.nolog:
  if cliArg.logfile:
    logfile = cliArg.logfile
  else:
    if cliArg.domain:
        logfile = "log/check-" + targetHostname + "-"+ currentDateTime + ".log"
    else:
        logfile = "log/check-" + targetIPaddress + "-"+ currentDateTime + ".log"
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
  print clr.Y + gfx.MINUS + "Skipping log file." + clr.END

### MALWAREBLOCKLISTS
if cliArg.malwarelists or cliArg.lists or cliArg.all:
  totalLines = 0
  if os.path.isfile(malwareSourceFile) == True:
      with open(malwareSourceFile) as sourcefile:
        sourceListLine = sourcefile.readlines()
        sourceCount = 0
      for line in sourceListLine:
          if line[:1] == "#":
              continue
          else:
              sourceCount += 1
      print clr.HDR + gfx.STAR + "Downloading and searching malware blocklists for domain name and IP address." + clr.END
      i = 0
      for sourceline in sourceListLine:
          sourceline = sourceline.split("|")
          sourceurl = sourceline[0].replace("\n", "").replace(" ", "")
          if sourceurl[:1] == "#":
              continue # Skip comment lines
          try:
              sourcename = sourceline[1].replace("\n", "")
          except IndexError:
              sourcename = sourceline[0].replace("\n", "") # If no name specified use URL.
          i += 1
          listfile = ""
          linecount = 0
          domainmatch = False
          ipmatch = False
          print gfx.PLUS + "Downloading from " + clr.BOLD + sourcename + clr.END + " [%s of %s sources]:" % (i, sourceCount) + clr.END
          try:
              data = ""
              req = requests.get(sourceurl, stream=True)
              filesize = req.headers.get('content-length')
              if not filesize:
                  # Assuming no content-length header
                  sys.stdout.write(gfx.PIPE + "[" + clr.G + "...................." + clr.END + "] Content-length not received." + clr.END)
                  data = req.content
                  cType = "text/plain"
              else:
                  cType = req.headers.get('content-type')
                  if not cType:
                      cType = "text/plain"
                  sys.stdout.write(gfx.PIPE + "[" + clr.R + "                    " + clr.END + "] Filesize: " + str(int(filesize) / 1024) + " kb \tContent type: " + str(cType) + " \r" + gfx.PIPE + "[")
                  part = int(filesize) / 20
                  c = 0
                  for chunk in req.iter_content(part):
                      c += 1
                      if c <= 20:
                          sys.stdout.write(clr.G + "." + clr.END)
                          sys.stdout.flush()
                      data = data + chunk
                  while c < 20:
                      c += 1
                      sys.stdout.write(clr.G + "." + clr.END)
                      sys.stdout.flush()
              if "application/zip" in cType:
                  zip_file_object = zipfile.ZipFile(StringIO.StringIO(data))
                  first_file = zip_file_object.namelist()[0]
                  file = zip_file_object.open(first_file)
                  listfile = file.read()
              elif "text/plain" in cType or "application/csv" in cType:
                  listfile = data
              else:
                  print gfx.FAIL + clr.R + "Unknown content type:", cType, ". Treating as plaintext."
                  runerrors = True
                  listfile = data
              for line in listfile.splitlines():
                  linecount += 1
              print "\r\n" + gfx.PIPE + "Searching from %s lines." % (linecount) + clr.END
              totalLines = totalLines + linecount
              for line in listfile.splitlines():
                if targetHostname in line:
                  domainmatch = True
                  print gfx.PIPE + clr.Y + "Domain match! " + clr.END + line.replace(targetHostname, clr.R + targetHostname + clr.END)
                if targetIPaddress in line:
                  ipmatch = True
                  print gfx.PIPE + clr.Y + "IP match! " + clr.END + line.replace(targetHostname, clr.R + targetIPaddress + clr.END)
                if targetIPrange in line:
                  ipmatch = True
                  print gfx.PIPE + clr.Y + "Range match! " + clr.END + line.replace(targetHostname, clr.R + targetIPrange + clr.END)

              if domainmatch == False and ipmatch == True:
                print gfx.PIPE + "Domain name not found." + clr.END
              elif ipmatch == False and domainmatch == True:
                print gfx.PIPE + "IP address not found." + clr.END
              else:
                print gfx.PIPE + "Domain name or IP address "+ clr.G + "not found" + clr.END + " in list." + clr.END

          except Exception:
              print gfx.FAIL + clr.R + "Failed: ", str(sys.exc_info()[0]), str(sys.exc_info()[1])
              runerrors = True
  else:
    print gfx.FAIL + clr.R + "No malwarelist file found at %s" & (malwareSourceFile)
    runerrors = True
  print gfx.PLUS + "A total of %s lines searched." % (totalLines)
else:
  print clr.Y + gfx.MINUS + "Skipping malwarelists query, Enable with \"--malwarelist\" or \"-ml\"" + clr.END

### SPAMLISTS
if cliArg.spamlists or cliArg.lists or cliArg.all:
    print clr.HDR + gfx.STAR + "Querying spamlists for %s..." % (targetIPaddress) + clr.END
    print gfx.PIPE
    for bl in sourceListSpamDNS:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(targetIPaddress).split("."))) + "." + bl
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            print gfx.PIPE + clr.Y + 'IP: %s IS listed in %s (%s: %s)' %(targetIPaddress, bl, answers[0], answer_txt[0]) + clr.END
        except dns.resolver.NXDOMAIN:
            print gfx.PIPE + 'IP: %s is NOT listed in %s' %(targetIPaddress, bl)
    print gfx.PIPE
else:
  print clr.Y + gfx.MINUS + "Skipping spam blocklists check, Enable with \"--spamlists\" or \"-sp\"" + clr.END

### VIRUSTOTAL
if (cliArg.virustotal or cliArg.lists or cliArg.all) and VirusTotalAPIKey != "":
  print clr.HDR + gfx.PLUS + "Querying VirusTotal for " + targetIPaddress + "..." + clr.END
  vturl = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
  parameters = {'ip': targetIPaddress, 'apikey': VirusTotalAPIKey}
  vtresponse = urllib.urlopen('%s?%s' % (vturl, urllib.urlencode(parameters))).read()
  vtresponse_dict = json.loads(vtresponse)
  if vtresponse_dict['response_code'] == 0:
    print clr.Y + gfx.STAR + "VirusTotal response: IP address not in dataset." + clr.END
  else:
    print clr.G + gfx.PLUS + "VirusTotal response code", vtresponse_dict['response_code'], vtresponse_dict['verbose_msg'] + clr.END
    print gfx.PIPE
    for entry in vtresponse_dict['resolutions']:
      print gfx.PIPE + " =>", entry['hostname'], "Last resolved:", entry['last_resolved']
    print gfx.PIPE
    if len(vtresponse_dict['detected_urls']) >= 1:
        print clr.G + gfx.PLUS + "Detections in this address:" + clr.END
        print gfx.PIPE
        for entry in vtresponse_dict['detected_urls']:
          print gfx.PIPE + entry['url'].replace("http", "hxxp") + clr.END
          if entry['positives'] >= 1:
            print gfx.PIPE + "Positives: ", clr.R + str(entry['positives']) + clr.END, "\tTotal:", entry['total'], "\tScan date:", entry['scan_date']
          else:
            print gfx.PIPE + "Positives: ", entry['positives'], "\tTotal:", entry['total'], "\tScan date:", entry['scan_date']
        print gfx.PIPE
else:
  print clr.Y + gfx.MINUS + "Skipping VirusTotal passive DNS, Enable with \"--virustotal\" or \"-vt\"" + clr.END

### PASSIVETOTAL
if (cliArg.passivetotal or cliArg.lists or cliArg.all) and PassiveTotalAPIKey != "":
  #disable passivetotal's error message
  requests.packages.urllib3.disable_warnings()
  #define API key
  pt = PassiveTotal(PassiveTotalAPIKey)
  print clr.HDR + gfx.PLUS + "Querying PassiveTotal for " + targetIPaddress + "..." + clr.END
  print gfx.PIPE + clr.END
  try:
      response = pt.get_passive(targetIPaddress)
  except ValueError:
      gfx.FAIL + clr.R + "Value error - no data received."
      runerrors = True
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
    print clr.R + "[!] Error when getting passive for %s: %s" % (targetIPaddress, response['error']) + clr.END
  print gfx.PIPE + clr.END
else:
  print clr.Y + gfx.MINUS + "Skipping PassiveTotal. Enable with argument \"--passive\" or \"-p\"" + clr.END


### GEOIP
if cliArg.geoip or cliArg.lists or cliArg.all:
    if os.path.isfile(GeoIPDatabaseFile) == True:
        latitude = ""
        longitude = latitude
        try:
            gi = GeoIP.open(GeoIPDatabaseFile, GeoIP.GEOIP_STANDARD)
            gir = gi.record_by_addr(targetIPaddress)
            print clr.HDR + gfx.PLUS + "Querying GeoIP database for " + targetIPaddress + "..." + clr.END
            if gir is None:
                print gfx.FAIL + clr.R + "No geodata found for IP address." + clr.END
            else:
                print gfx.PIPE + clr.END
                for key, value in gir.iteritems():
                    if key == "latitude":
                        latitude = value
                    elif key == "longitude":
                        longitude = value
                    print gfx.PIPE + str(key) + ": " + str(value)
                if latitude != "" and longitude != "":
                    print gfx.PIPE + "Google maps link for location: " + clr.UL + "https://maps.google.com/maps?q="+str(latitude)+","+str(longitude) + clr.END
                print gfx.PIPE + clr.END
                if cliArg.openlink:
                    webbrowser.open('https://maps.google.com/maps?q='+str(latitude)+','+str(longitude))
        except Exception:
            print gfx.FAIL + clr.R + "Failed: ", str(sys.exc_info()[0]), str(sys.exc_info()[1])
            runerrors = True
    else:
        print gfx.FAIL + clr.R + "Database not found at ", GeoIPDatabaseFile + clr.END
        print gfx.FAIL + clr.R + "Please install GeoIP database. http://dev.maxmind.com/geoip/legacy/install/city/" + clr.END
        runerrors = True
else:
    print clr.Y + gfx.MINUS + "Skipping GeoIP. Enable with argument \"--geoip\" or \"-g\""

### WHOIS
if cliArg.whois or cliArg.lists or cliArg.all:
  results = results2 = ""
  try:
    results = subprocess.check_output("whois "+targetIPaddress, shell=True)
  except subprocess.CalledProcessError:
    gfx.FAIL + clr.R + "Whois returned an error."
    runerrors = True
  if targetHostname != "Not defined":
    try:
      results2 = subprocess.check_output("whois "+targetHostname, shell=True)
    except subprocess.CalledProcessError:
      gfx.FAIL + clr.R + "Whois returned an error."
      runerrors = True
  if results:
    print clr.HDR + gfx.STAR + "Querying IP Address " + targetIPaddress + clr.END
    for line in results.splitlines():
      if "#" in line:
        ()
      elif ("abuse" in line and "@" in line) or "address" in line or "person" in line or "phone" in line:
        print gfx.PIPE + clr.BOLD + clr.B + line + clr.END
      elif "descr" in line:
        print gfx.PIPE + clr.BOLD + clr.Y + line + clr.END
      else:
        print gfx.PIPE + line  + clr.END
  if results2:
    print clr.HDR +  gfx.PLUS + "Resolved address " + targetIPaddress + " for domain " + targetHostname + clr.END
    for line in results2.splitlines():
      if "#" in line:
        ()
      elif ("abuse" in line and "@" in line) or "address" in line or "person" in line or "phone" in line:
        print gfx.PIPE + clr.BOLD + clr.B + line + clr.END
      elif "descr" in line:
        print gfx.PIPE + clr.BOLD + clr.Y + line + clr.END
      else:
        print gfx.PIPE + line  + clr.END
else:
  print clr.Y + gfx.MINUS + "Skipping Whois. Enable with argument \"--whois\" or \"-w\""


## SEE IF IP IS LIVE
if targetIPaddress != "127.0.0.1":
    iptype = IP(targetIPaddress).iptype()
else:
    iptype="PUBLIC"
if iptype == "PRIVATE" or iptype == "LOOPBACK":
  print clr.R + gfx.STAR + "IP address type is \'" + iptype.lower() + "\', can not process. Exiting..."
  exit()
else:
  print clr.HDR + gfx.STAR + "Fully Qualified Doman Name: " + socket.getfqdn(targetIPaddress) + clr.END

#### PING
if cliArg.ping or cliArg.probes or cliArg.all:
  print clr.HDR + gfx.PLUS + "Pinging target, skip with CTRL-C..." + clr.END
  print gfx.PIPE + clr.END
  try:
    response = os.system("ping -c 1 " + targetIPaddress + " > /dev/null 2>&1")
    if response == 0:
      print gfx.PIPE + clr.G + targetIPaddress, 'is responding to ping.' + clr.END
    else:
      print gfx.PIPE + clr.R + targetIPaddress, 'is not responding to ping.' + clr.END
    print gfx.PIPE + clr.END
  except KeyboardInterrupt:
    print clr.Y + gfx.MINUS + "Skipping ping." + clr.END
else:
  print clr.Y + gfx.MINUS + "Skipping ping, Enable pinging with \"--ping\" or \"-P\"" + clr.END

### SCANPORTS & SCANHEADERS
if cliArg.scanports or cliArg.probes or cliArg.all:
    print clr.HDR + gfx.PLUS + "Scanning common ports..." + clr.END
    print gfx.PIPE + clr.END
    socket.setdefaulttimeout(1)
    try:
      for port in targetPortscan:
        if cliArg.scanheaders or cliArg.probes or cliArg.all:
            print gfx.PIPE + "Scanning port " + str(port) + " and attempting to get headers..." + clr.END
        else:
            print gfx.PIPE + "Scanning port " + str(port) + "..." + clr.END
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((targetIPaddress, port))
        if result == 0:
          print gfx.PIPE + clr.G + "port " + str(port) + " is open." + clr.END
          if (cliArg.scanheaders or cliArg.probes or cliArg.all) and targetHostname != "Not defined":
            url = "http://" + targetHostname
            try:
              print clr.HDR + gfx.PLUS + "Trying to retrieve http://" + targetHostname + " from port " + str(port) + clr.END
              page = urllib2.urlopen('http://' + targetHostname)
              print clr.HDR + gfx.PLUS + "Getting headers..."+clr.END
              for line in str(page.info()).splitlines():
                  print clr.BOLD + gfx.PIPE + line + clr.END
            except Exception,e:
              print clr.R + "[!] " + str(e) + clr.END
        sock.close()
    except KeyboardInterrupt:
      print clr.R + gfx.STAR + "Caught Ctrl+C, interrupting..."
      sys.exit()
    except socket.gaierror:
      print clr.R + gfx.STAR + "Hostname could not be resolved. Exiting..."
      sys.exit()
    except socket.error:
      print clr.R + gfx.STAR + "Couldn't connect to server."
      sys.exit()
    print gfx.PIPE + clr.END
else:
    print clr.Y + gfx.MINUS + "Skipping portscan. Enable scanning with argument \"--scan\" or \"-s\""
if logfile != "":
  print clr.HDR + gfx.STAR + "Writing log file to " + logfile + clr.END

if runerrors == True:
    print clr.Y + gfx.STAR + "Done, with errors." + clr.END
else:
    print clr.HDR + gfx.STAR + "Done, no errors." + clr.END

exit()
