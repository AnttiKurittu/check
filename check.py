#coding=UTF-8

# See https://github.com/AnttiKurittu/check/ for details.

import datetime
startTime = datetime.datetime.now()
import os, sys, socket, urllib, urllib2, json, argparse, webbrowser, subprocess, zipfile, dns.resolver, requests, GeoIP, StringIO, operator
from passivetotal import PassiveTotal
from IPy import IP

parser = argparse.ArgumentParser(description='Get actions')
parser.add_argument("-d", "--domain", metavar='domain name', type=str, help="Target domain name")
parser.add_argument("-i", "--ip", metavar='IP address', type=str, help="Target IP address")
parser.add_argument("-a", "--all", help="run all queries", action="store_true")
parser.add_argument("-l", "--lists", help="run all third-party queries (malwarelists, spamlists, virustotal, passivetotal, whois, geoip)", action="store_true")
parser.add_argument("-p", "--probes", help="run all host-contacting probes (ping, scan ports, scan headers)", action="store_true")
parser.add_argument("-pg", "--ping", help="Ping IP address", action="store_true")
parser.add_argument("-ws", "--whois", help="Query WHOIS information", action="store_true")
parser.add_argument("-sp", "--scanports", help="Scan common ports", action="store_true")
parser.add_argument("-gi", "--geoip", help="Query GeoIP database", action="store_true")
parser.add_argument("-sh", "--scanheaders", help="Scan common ports and try to retrieve HTTP headers", action="store_true")
parser.add_argument("-gs", "--googlesafebrowsing", help="Check Google Safe Browsing database", action="store_true")
parser.add_argument("-wt", "--weboftrust", help="Query Web Of Trust database", action="store_true")
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

def terminate():
    stopTime = datetime.datetime.now()
    totalTime = stopTime - startTime
    if len(hasError) > 0:
        modHeader("Executed %s modules with errors in %s, runtime %s seconds." % (len(run), ", ".join(hasError), totalTime.seconds))
    else:
        modHeader("Executed %s modules in %s seconds." % (len(run), totalTime.seconds))
    modHeader("Skipped %s modules."  % len(notRun))
    exit()

def throwError(message, module):
    if module != "":
        print gfx.FAIL + clr.R + ("%s: %s" % (module, message)) + clr.END
        hasError.append(module)
    else:
        print gfx.FAIL + clr.R + ("%s" % message) + clr.END
    return True
def modHeader(message):
    print gfx.STAR + clr.HDR + message + clr.END
    return True

## Specify resources and API keys
currentDateTime = str(datetime.datetime.now().strftime("%Y-%m-%d-%H:%M"))
GeoIPDatabaseFile = "/usr/local/share/GeoIP/GeoLiteCity.dat" # Specify database file location
targetPortscan = [80, 443, 8000, 20, 21, 22, 23, 25, 53] # What ports to scan
malwareSourceFile = "malwaresources.txt"
#sourceListURL = ['http://www.malware-domains.com/files/domains.zip', 'http://www.malwaredomainlist.com/mdlcsv.php', 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist', 'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist', 'https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset']
sourceListSpamDNS = ["zen.spamhaus.org", "spam.abuse.ch", "cbl.abuseat.org", "virbl.dnsbl.bit.nl", "dnsbl.inps.de",
"ix.dnsbl.manitu.net", "dnsbl.sorbs.net", "bl.spamcannibal.org", "bl.spamcop.net", "xbl.spamhaus.org", "pbl.spamhaus.org",
"dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net", "db.wpbl.info"] # What sources to query for malwarelists
headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36', 'referer': 'https://www.google.com'}
hasError = [] # Gather erring modules
logfile = "" # Set variable as blank to avoid errors further on.
notRun = [] # Gather skipped modules
run = [] # Gather executed modules

try:
    VirusTotalAPIKey = os.environ['VTAPIKEY'] ### Export your api keys to shell variables or put them here, add "Export VTAPIKEY=yourapikey to .bashrc or whatever your using."
except KeyError:
    VirusTotalAPIKey = ""
    throwError("VirusTotal API key not present.", "VirusTotal")
try:
    PassiveTotalAPIKey = os.environ['PTAPIKEY'] ### same here.
except KeyError:
    PassiveTotalAPIKey = ""
    throwError("PassiveTotal API key not present.", "PassiveTotal")
try:
    GoogleAPIKey = os.environ['GAPIKEY'] ### same here.
except KeyError:
    GoogleAPIKey = ""
    throwError("Google API key not present.", "Google Safe Browsing")
try:
    WOTAPIKey = os.environ['WOTAPIKEY'] ### same here.
except KeyError:
    WOTAPIKey = ""
    throwError("Web Of Trust API key not present.", "Web Of Trust")

def validate_ip(s): # Validate IP address format
    try:
        socket.inet_aton(s)
    except Exception:
        return False
    return True

if cliArg.ip and cliArg.domain:
    throwError("Specify an IP address or domain, not both! Exiting...", "Dual target")
    terminate()
if cliArg.ip:
    if validate_ip(cliArg.ip) == False:
        throwError("Invalid IP address, exiting...", "Validate IP")
        terminate()
    else:
        targetIPaddress = cliArg.ip
        targetHostname = "Not defined"
elif cliArg.domain:
    targetHostname = cliArg.domain
    try:
        targetIPaddress = socket.gethostbyname(cliArg.domain)
    except socket.gaierror:
        throwError("Resolve error, assignign 127.0.0.1 as ip", "Domain resolve")
        throwError("Can not resolve IP address, assignigin 127.0.0.1...", "Domain resolve")
        targetIPaddress = "127.0.0.1"
else:
    throwError("No target given, exiting...", "Target")
    terminate()

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
                self.log.write(message.replace("\033[95m", "")\
                .replace("\033[94m", "").replace("\033[93m", "")\
                .replace("\033[92m", "").replace("\033[91m", "")\
                .replace("\033[0m", "").replace("\033[1m", "")\
                .replace("\033[4m", ""))
            def flush(self):
                self.terminal.flush()
    sys.stdout = Logger(logfile)

targetIPrange = targetIPaddress.split(".")
targetIPrange = targetIPrange[0] + "." + targetIPrange[1] + "." + targetIPrange[2] + ".0"
modHeader("Using IP address %s" % targetIPaddress)

if targetIPaddress != "127.0.0.1":
    iptype = IP(targetIPaddress).iptype()
else:
    iptype="PUBLIC"

if iptype == "PRIVATE" or iptype == "LOOPBACK":
    print modHeader("IP address type is \'" + iptype.lower() + "\', this may lead to errors.")
else:
    "Fully Qualified Doman Name: " + socket.getfqdn(targetIPaddress) + clr.END

### GOOGLE SAFE BROWSING API LOOKUP
if (cliArg.googlesafebrowsing or cliArg.lists or cliArg.all) and targetHostname != "Not defined":
    run.append("Google Safe Browsing")
    modHeader("Querying Google Safe Browsing API with domain name")
    target = 'http://' + targetHostname + '/'
    parameters = {'client': 'check-lookup-tool', 'key': GoogleAPIKey, 'appver': '1.0', 'pver': '3.1', 'url': target}
    reply = requests.get("https://sb-ssl.google.com/safebrowsing/api/lookup", params=parameters, headers=headers)
    if reply.status_code == 200:
        print gfx.PIPE + clr.Y + "Status %s: Address http://%s/ found:" % (reply.status_code, targetHostname), reply.text + clr.END
    elif reply.status_code == 204:
        print gfx.PIPE + clr.G + "Status %s: The requested URL is legitimate." % (reply.status_code) + clr.END
    elif reply.status_code == 400:
        throwError("Status %s: Bad Request." % reply.status_code, "Google Safe Browsing")
    elif reply.status_code == 401:
        throwError("Status %s: Not Authorized" % (reply.status_code), "Google Safe Browsing")
    elif reply.status_code == 503:
        throwError("Status %s: Service Unavailable" % (reply.status_code), "Google Safe Browsing")
    else:
        throwError("Status %s: Unhandled reply: " % (reply.status_code), "Google Safe Browsing")
    print gfx.PIPE
else:
    notRun.append("Google Safe Browsing")

### WEB OF TRUST API LOOKUP
if (cliArg.weboftrust or cliArg.lists or cliArg.all) and targetHostname != "Not defined":
    run.append("Web Of Trust")
    modHeader("Querying Web Of Trust reputation API with domain name")
    target = 'http://' + targetHostname + '/'
    parameters = {'hosts': targetHostname + "/", 'key': WOTAPIKey}
    reply = requests.get("http://api.mywot.com/0.4/public_link_json2", params=parameters, headers=headers)
    reply_dict = json.loads(reply.text)
    categories = {
    '101': clr.R + 'Negative: Malware or viruses' + clr.END,
    '102': clr.R + 'Negative: Poor customer experience' + clr.END,
    '103': clr.R + 'Negative: Phishing' + clr.END,
    '104': clr.R + 'Negative: Scam' + clr.END,
    '105': clr.R + 'Negative: Potentially illegal' + clr.END,
    '201': clr.Y + 'Questionable: Misleading claims or unethical' + clr.END,
    '202': clr.Y + 'Questionable: Privacy risks' + clr.END,
    '203': clr.Y + 'Questionable: Suspicious' + clr.END,
    '204': clr.Y + 'Questionable: Hate, discrimination' + clr.END,
    '205': clr.Y + 'Questionable: Spam' + clr.END,
    '206': clr.Y + 'Questionable: Potentially unwanted programs' + clr.END,
    '207': clr.Y + 'Questionable: Ads / pop-ups' + clr.END,
    '301': clr.G + 'Neutral: Online tracking' + clr.END,
    '302': clr.G + 'Neutral: Alternative or controversial medicine' + clr.END,
    '303': clr.G + 'Neutral: Opinions, religion, politics ' + clr.END,
    '304': clr.G + 'Neutral: Other ' + clr.END,
    '401': clr.Y + 'Child safety: Adult content' + clr.END,
    '402': clr.Y + 'Child safety: Incindental nudity' + clr.END,
    '403': clr.R + 'Child safety: Gruesome or shocking' + clr.END,
    '404': clr.G + 'Child safety: Site for kids' + clr.END,
    '501': clr.G + 'Positive: Good site' + clr.END}
    if reply.status_code == 200:
        hasKeys = False
        for key, value in reply_dict[targetHostname].iteritems():
            if key == "target":
                print gfx.PLUS + "Server response OK, Web Of Trust Reputation Score for", clr.BOLD + value + ":" + clr.END
            elif key == "1":
                () # Deprecated
            elif key == "2":
                () # Deprecated
            elif key == "0" or key == "4":
                hasKeys = True
                if int(value[0]) >= 0:
                    assessment = clr.R + "Very poor" + clr.END
                if int(value[0]) >= 20:
                    assessment = clr.R + "Poor" + clr.END
                if int(value[0]) >= 40:
                    assessment = clr.Y + "Unsatisfactory" + clr.END
                if int(value[0]) >= 60:
                    assessment = clr.G + "Good" + clr.END
                if int(value[0]) >= 80:
                    assessment = clr.G + "Excellent" + clr.END
                if key == "0":
                    print gfx.PIPE
                    print gfx.PIPE + "Trustworthiness:\t %s (%s) \t[%s%% confidence]" % (value[0], assessment, value[1])
                elif key == "4":
                    print gfx.PIPE + "Child safety:\t %s (%s) \t[%s%% confidence]" % (value[0], assessment, value[1])
            elif key == "categories":
                print gfx.PIPE
                hasKeys = True
                for e,s in value.iteritems():
                    print gfx.PIPE + "Category:\t %s \t[%s%% confidence]" % (categories[e], s)
                print gfx.PIPE
            elif key == "blacklists":
                hasKeys = True
                for e,s in value.iteritems():
                    print gfx.PIPE + "Blacklisted:\t %s \tID: %s" % (e, s)
            else:
                print "Unknown key", key, " => ", value
    if hasKeys == False:
        print gfx.PIPE + clr.G + "Web Of Trust has no records for", targetHostname + clr.END
        print gfx.PIPE
    if reply.status_code != 200:
        throwError("Server returned status code %s see https://www.mywot.com/wiki/API for details." % reply.status_code, "Web Of Trust")
else:
    notRun.append("Web Of Trust")


### MALWAREBLOCKLISTS
if cliArg.malwarelists or cliArg.lists or cliArg.all:
  run.append("Malware blacklists")
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
      modHeader("Downloading and searching malware blocklists for address.")
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
              try:
                  req = requests.get(sourceurl, stream=True, headers=headers)
              except requests.exceptions.ConnectionError:
                  print gfx.PIPE + "[" + clr.R + "Fail!" + clr.END + "] Unable to connect to %s" % (sourcename)
                  continue
              try:
                  cd = req.headers['Content-Disposition']
              except Exception:
                  cd = ""
              filesize = req.headers.get('content-length')
              if not filesize:
                  # Assuming no content-length header
                  sys.stdout.write(gfx.PIPE + "[" + clr.G + "Done!" + clr.END + "] Content-length not received. " + cd + clr.END)
                  data = req.content
                  cType = "text/plain"
              else:
                  cType = req.headers.get('content-type')
                  if not cType:
                      cType = "text/plain"
                  sys.stdout.write(gfx.PIPE + "[" + clr.R + "     " + clr.END + "] Filesize: " + str(int(filesize) / 1024) + " kb \tContent type: " + str(cType) + " \r" + gfx.PIPE + "[")
                  part = int(filesize) / 5
                  c = 0
                  for chunk in req.iter_content(part):
                      c += 1
                      if c <= 5:
                          if c == 1:
                              sys.stdout.write(clr.G + "D" + clr.END)
                          if c == 2:
                              sys.stdout.write(clr.G + "o" + clr.END)
                          if c == 3:
                              sys.stdout.write(clr.G + "n" + clr.END)
                          if c == 4:
                              sys.stdout.write(clr.G + "e" + clr.END)
                          if c == 5:
                              sys.stdout.write(clr.G + "!" + clr.END)
                          sys.stdout.flush()
                      data = data + chunk
                  while c < 5: # Fill the meter if the chunks round down.
                      c += 1
                      sys.stdout.write(clr.G + "!" + clr.END)
                      sys.stdout.flush()
              if "application/zip" in cType:
                  filelist = {}
                  zip_file_object = zipfile.ZipFile(StringIO.StringIO(data))
                  for info in zip_file_object.infolist(): # Get zip contents and put to a list
                      filelist[info.filename] = info.file_size # Add files to a list
                  sortedlist = sorted(filelist.items(), key=operator.itemgetter(1)) # Sort list by value; largest file is last
                  for key, value in sortedlist: # Iterate over list - last assigned value is the largest file
                      largestfile = key
                      largestsize = value
                  sys.stdout.write("\r\n" + gfx.PIPE + "Decompressing and using largest file in archive: %s (%s bytes)." % (largestfile, largestsize))
                  file = zip_file_object.open(largestfile)
                  listfile = file.read()
              elif "text/plain" in cType or "application/csv" in cType:
                  listfile = data
              else:
                  throwError("Unknown content type:", cType, ". Treating as plaintext.", "Malwarelist")
                  listfile = data
              for line in listfile.splitlines():
                  linecount += 1
              print "\r\n" + gfx.PIPE + "Searching from %s lines." % (linecount) + clr.END
              totalLines = totalLines + linecount
              for line in listfile.splitlines():
                  if targetHostname != "Not defined":
                      if targetHostname in line:
                          domainmatch = True
                          print gfx.PIPE + clr.Y + "Domain match! " + clr.END + line.replace(targetHostname, clr.R + targetHostname + clr.END)
                  if targetIPaddress in line:
                      ipmatch = True
                      print gfx.PIPE + clr.Y + "IP match! " + clr.END + line.replace(targetHostname, clr.R + targetIPaddress + clr.END)
                  if targetIPrange in line:
                      ipmatch = True
                      print gfx.PIPE + clr.Y + "Range match! " + clr.END + line.replace(targetHostname, clr.R + targetIPrange + clr.END)
              if domainmatch == False and ipmatch == True and targetHostname != "Not defined":
                  print gfx.PIPE + "Domain name not found." + clr.END
              elif ipmatch == False and domainmatch == True:
                  print gfx.PIPE + "IP address not found." + clr.END
              else:
                  print gfx.PIPE + "Address "+ clr.G + "not found" + clr.END + " in list." + clr.END

          except Exception:
              throwError("Failed: %s %s " % (str(sys.exc_info()[0]), str(sys.exc_info()[1])), "Malwarelist")
              runerrors = True
  else:
    throwError("No malwarelist file found at %s" % malwareSourceFile, "Malwarelist")
    runerrors = True
  print gfx.PLUS + "A total of %s lines searched." % (totalLines) + clr.END
  print gfx.PIPE
else:
    notRun.append("Malware blacklists")

### SPAMLISTS
if cliArg.spamlists or cliArg.lists or cliArg.all:
    run.append("Spamlists")
    modHeader("Querying spamlists for %s..." % targetIPaddress)
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
    notRun.append("Spamlists")

### VIRUSTOTAL
if (cliArg.virustotal or cliArg.lists or cliArg.all) and VirusTotalAPIKey != "":
  run.append("VirusTotal")
  modHeader("Querying VirusTotal for %s..." % targetIPaddress)
  vturl = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
  parameters = {'ip': targetIPaddress, 'apikey': VirusTotalAPIKey}
  vtresponse = urllib.urlopen('%s?%s' % (vturl, urllib.urlencode(parameters))).read()
  vtresponse_dict = json.loads(vtresponse)
  if vtresponse_dict['response_code'] == 0:
    print gfx.STAR + clr.Y + "VirusTotal response: IP address not in dataset." + clr.END
  else:
    print gfx.PLUS + clr.G + "VirusTotal response code", vtresponse_dict['response_code'], vtresponse_dict['verbose_msg'] + clr.END
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
    notRun.append("VirusTotal")

### PASSIVETOTAL
if (cliArg.passivetotal or cliArg.lists or cliArg.all) and PassiveTotalAPIKey != "":
  run.append("PassiveTotal")
  #disable passivetotal's error message
  requests.packages.urllib3.disable_warnings()
  #define API key
  pt = PassiveTotal(PassiveTotalAPIKey)
  modHeader("Querying PassiveTotal for %s..." % targetIPaddress)
  try:
      response = ""
      response = pt.get_passive(targetIPaddress)
  except ValueError:
      throwError("Value error - no data received.", "PassiveTotal")
  if response == "":
      gfx.FAIL + clr.R + "Empty response, maybe your over your quota?"
  elif response['success']:
    print gfx.PIPE + "Query:", response['raw_query']
    print gfx.PIPE + "First Seen:", response['results']['first_seen']
    print gfx.PIPE + "Last Seen:", response['results']['last_seen']
    print gfx.PIPE + "Resolve Count: ", response['result_count']
    print gfx.PIPE + "Resolutions"
    response = response['results']
    for resolve in response['records']:
      print gfx.PIPE + "==> ", resolve['resolve'], "\t", resolve['firstSeen'], "\t", resolve['lastSeen'], "\t", ', '.join([ str(x) for x in resolve['source'] ])
  else:
    throwError("%s" % response['error'], "PassiveTotal")
  print gfx.PIPE
else:
    notRun.append("PassiveTotal")


### GEOIP
if cliArg.geoip or cliArg.lists or cliArg.all:
    run.append("GeoIP")
    if os.path.isfile(GeoIPDatabaseFile) == True:
        latitude = ""
        longitude = latitude
        try:
            gi = GeoIP.open(GeoIPDatabaseFile, GeoIP.GEOIP_STANDARD)
            gir = gi.record_by_addr(targetIPaddress)
            modHeader("Querying GeoIP database for %s" % targetIPaddress)
            if gir is None:
                throwError("No geodata found for IP address.", "GeoIP")
            else:
                for key, value in gir.iteritems():
                    if key == "latitude":
                        latitude = value
                    elif key == "longitude":
                        longitude = value
                    print gfx.PIPE + str(key) + ": " + str(value)
                if latitude != "" and longitude != "":
                    print gfx.PIPE + "Google maps link for location: " + clr.UL + "https://maps.google.com/maps?q="+str(latitude)+","+str(longitude) + clr.END
                if cliArg.openlink:
                    webbrowser.open('https://maps.google.com/maps?q='+str(latitude)+','+str(longitude))
        except Exception:
            throwError("Failed: %s %s " % (str(sys.exc_info()[0]), str(sys.exc_info()[1])), "GeoIP")
    else:
        throwError("Database not found at %s" % GeoIPDatabaseFile, "GeoIP")
        throwError("Please install GeoIP database. http://dev.maxmind.com/geoip/legacy/install/city/", "")
    print gfx.PIPE
else:
    notRun.append("GeoIP")

### WHOIS
if cliArg.whois or cliArg.lists or cliArg.all:
  run.append("Whois")
  results = results2 = ""
  try:
    results = subprocess.check_output("whois "+targetIPaddress, shell=True)
  except subprocess.CalledProcessError:
    throwError("Whois returned an error.", "Whois")
  if targetHostname != "Not defined":
    try:
      results2 = subprocess.check_output("whois "+targetHostname, shell=True)
    except subprocess.CalledProcessError:
      throwError("Whois returned an error.", "Whois")
  if results:
    modHeader("Querying IP Address %s" % targetIPaddress)
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
    print gfx.PIPE
else:
    notRun.append("Whois")

#### PING
if cliArg.ping or cliArg.probes or cliArg.all:
    run.append("Ping")
    modHeader("Pinging %s, skip with CTRL-C..." % targetIPaddress)
    try:
        response = os.system("ping -c 1 " + targetIPaddress + " > /dev/null 2>&1")
        if response == 0:
            print gfx.PIPE + clr.G + targetIPaddress, 'is responding to ping.' + clr.END
        else:
            print gfx.PIPE + clr.R + targetIPaddress, 'is not responding to ping.' + clr.END
            print gfx.PIPE + clr.END
    except KeyboardInterrupt:
        print clr.Y + gfx.MINUS + "Skipping ping." + clr.END
        notRun.append("Ping")
    print gfx.PIPE
else:
    notRun.append("Ping")

### SCANPORTS & SCANHEADERS
if cliArg.scanports or cliArg.scanheaders or cliArg.probes or cliArg.all:
    run.append("Portscan")
    modHeader("Scanning common ports...")
    socket.setdefaulttimeout(1)
    openports = []
    try:
        for port in targetPortscan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((targetIPaddress, port))
            if result == 0:
                print gfx.PIPE + clr.G + "port " + str(port) + " is open." + clr.END
                openports.append(port)
            else:
                print gfx.PIPE + "Port %s is closed." % port
            sock.close()

        if (cliArg.scanheaders or cliArg.probes or cliArg.all) and targetHostname != "Not defined":
            for port in openports:
                url = "http://" + targetHostname
                try:
                    if port == 443:
                        protocol = "https://"
                    else:
                        protocol = "http://"
                    print gfx.PIPE
                    print gfx.PLUS + "Getting headers for %s%s:%s" % (protocol, targetHostname, port) + clr.END
                    page = requests.get('%s%s:%s' % (protocol, targetHostname, port), headers=headers)
                    print gfx.PIPE + clr.BOLD + "Server response code: %s" % page.status_code + clr.END
                    for key, value in page.headers.items():
                        print gfx.PIPE + clr.BOLD + "%s: %s" % (key, value) + clr.END
                except Exception,e:
                    throwError(str(e), "Headerscan")

    except KeyboardInterrupt:
        print clr.R + gfx.STAR + "Caught Ctrl+C, interrupting..."
        sys.terminate()
    except socket.gaierror:
        print clr.R + gfx.STAR + "Hostname could not be resolved. Exiting..."
        sys.terminate()
    except socket.error:
        print clr.R + gfx.STAR + "Couldn't connect to server."
        sys.terminate()
    print gfx.PIPE + clr.END
else:
    notRun.append("Portscan")

if logfile != "":
    modHeader("Writing log file to %s" % logfile)

terminate()
