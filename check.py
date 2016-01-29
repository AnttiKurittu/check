#coding=UTF-8

# See https://github.com/AnttiKurittu/check/ for details.

import datetime

startTime = datetime.datetime.now()

import os, sys, socket, urllib, urllib2, json, argparse, webbrowser, subprocess,\
    zipfile, dns.resolver, requests, GeoIP, StringIO, operator, random, hashlib,\
    dateutil.parser, time
from passivetotal import PassiveTotal
from IPy import IP

parser = argparse.ArgumentParser(description='Get actions')
parser.add_argument("-d", "--domain", metavar='domain name', type=str, help="Target domain name")
parser.add_argument("-i", "--ip", metavar='IP address', type=str, help="Target IP address")
parser.add_argument("-a", "--all", help="run all queries", action="store_true")
parser.add_argument("-l", "--lists", help="run all third-party queries (blacklists, spamlists, virustotal, passivetotal, whois, geoip)", action="store_true")
parser.add_argument("-p", "--probes", help="run all host-contacting probes (ping, scan ports, scan headers, certificate)", action="store_true")
parser.add_argument("-pg", "--ping", help="Ping IP address", action="store_true")
parser.add_argument("-ws", "--whois", help="Query WHOIS information", action="store_true")
parser.add_argument("-cr", "--cert", help="Display certificate information via OpenSSL", action="store_true")
parser.add_argument("-sp", "--scanports", help="Scan common ports", action="store_true")
parser.add_argument("-gi", "--geoip", help="Query GeoIP database", action="store_true")
parser.add_argument("-sh", "--scanheaders", help="Scan common ports and try to retrieve HTTP headers", action="store_true")
parser.add_argument("-gs", "--googlesafebrowsing", help="Check Google Safe Browsing database", action="store_true")
parser.add_argument("-wt", "--weboftrust", help="Query Web Of Trust database", action="store_true")
parser.add_argument("-sl", "--spamlists", help="Check SURBL and SpamHaus blocklists for IP", action="store_true")
parser.add_argument("-bl", "--blacklists", help="Check blacklists for target", action="store_true")
parser.add_argument("-pt", "--passivetotal", help="Query passive DNS records from PassiveTotal", action="store_true")
parser.add_argument("-vt", "--virustotal", help="Query passive DNS records from VirusTotal", action="store_true")
parser.add_argument("-nt", "--note", metavar='Add a note', type=str, help="Add a note to the output, this could be a project name or description of address.")
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

## Specify resources and API keys
scriptpath = os.path.dirname(sys.argv[0]) + "/"
if scriptpath is "/" or scriptpath is "":
    scriptpath = "./"
currentDateTime = str(datetime.datetime.now().strftime("%Y-%m-%d-%H:%M"))
eNow = int(time.mktime(dateutil.parser.parse(currentDateTime).timetuple()))
GeoIPDatabaseFile = "/usr/local/share/GeoIP/GeoLiteCity.dat" # Specify database file location
targetPortscan = [80, 443, 8000, 20, 21, 22, 23, 25, 53] # What ports to scan
blacklistSourceFile = scriptpath + "blacklists.txt"
sourceListSpamDNS = [
        "zen.spamhaus.org", "spam.abuse.ch", "cbl.abuseat.org",
        "virbl.dnsbl.bit.nl", "dnsbl.inps.de", "ix.dnsbl.manitu.net",
        "dnsbl.sorbs.net", "bl.spamcannibal.org", "bl.spamcop.net",
        "xbl.spamhaus.org", "pbl.spamhaus.org","dnsbl-1.uceprotect.net",
        "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net", "db.wpbl.info"
        ]
uapool = [
         'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
         'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36',
         'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
         'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
         'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko',
         'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 7.0; InfoPath.3; .NET c 3.1.40767; Trident/6.0; en-IN)',
         'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
         'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
         'Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)',
         'Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)',
         'Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)',
         'Mozilla/1.22 (compatible; MSIE 10.0; Windows 3.1)',
         'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1',
         'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0',
         'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A'
         ]
headers = {'user-agent': 'Mozilla/5.0 (Check.py extended address information lookup tool)', 'referer': 'https://www.github.com/AnttiKurittu/check'}
hasError = [] # Gather erring modules
logfile = None # Set variable as blank to avoid errors further on.
notRun = [] # Gather skipped modules
run = [] # Gather executed modules

if cliArg.monochrome:
  class c:
      HDR = ''
      B = ''
      G = ''
      Y = ''
      R = ''
      END = ''
      BOLD = ''
      UL = ''
else:
  class c:
      HDR = '\033[95m'
      B = '\033[94m'
      G = '\033[92m'
      Y = '\033[93m'
      R = '\033[91m'
      END = '\033[0m'
      BOLD = '\033[1m'
      UL = '\033[4m'

if cliArg.nogfx:
  class g:
      STAR = ''
      PLUS = ''
      PIPE = ''
      FAIL = ''
      MINUS = ''
else:
  class g:
      STAR = "[*] "
      PLUS = "[+] "
      PIPE = " |  "
      FAIL = "[!] "
      MINUS = "[-] "

class Logger(object): # Log output to file, remove colors.
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

def terminate(): # Graceful exit.
    stopTime = datetime.datetime.now()
    totalTime = stopTime - startTime
    if len(hasError) > 0:
        printh("Executed %s modules with errors in %s, runtime %s seconds." % (len(run), ", ".join(hasError), totalTime.seconds))
    else:
        printh("Executed %s modules in %s seconds." % (len(run), totalTime.seconds))
    printh("Skipped %s modules."  % len(notRun))
    exit()

def trimcache(h): # Removes cache files older than h, returns removed megabyte amount.
    filelist = [ f for f in os.listdir(scriptpath + "cache") ]
    removedSize = 0
    cacheSize = 0
    for f in filelist:
        filesize = os.path.getsize(scriptpath + "cache/" + f)
        cacheSize = cacheSize + filesize
        filedate = 0
        difference = 0
        if len(f) == 43:
            filedate = f.split("-")
            filedate = int(filedate[0])
            difference = (eNow - filedate) / 8600
            if difference >= h:
                removedSize = removedSize + filesize
                os.remove(scriptpath + "cache/" + f)
    megabytesRemoved = removedSize / 1000000
    megabytesLeft = (cacheSize - removedSize) / 1000000
    return megabytesRemoved, megabytesLeft

def printe(message, module):
    if module != "":
        print g.FAIL + c.R + ("%s: %s" % (module, message)) + c.END
        hasError.append(module)
    else:
        print g.FAIL + c.R + ("%s" % message) + c.END
    return True

def printh(message):
    print g.STAR + c.HDR + message + c.END
    return True

def validate_ip(ip): # Validate IP address format
    try:
        socket.inet_aton(ip)
    except Exception:
        return False
    return True

### PROCESS CLI ARGUMENTS

if cliArg.ip and cliArg.domain:
    printe("Specify an IP address or domain, not both! Exiting...", "Dual target")
    terminate()
if cliArg.ip:
    if validate_ip(cliArg.ip) == False:
        printe("Invalid IP address, exiting...", "Validate IP")
        terminate()
    else:
        targetIPaddress = cliArg.ip
        targetDomain = "Not defined"
elif cliArg.domain:
    targetDomain = cliArg.domain.replace("https://", "").replace("http://", "").replace("/", "")
    try:
        targetIPaddress = socket.gethostbyname(targetDomain)
    except socket.gaierror:
        printe("Resolve error, assignign 127.0.0.1 as ip", "Domain resolve")
        printe("Can not resolve IP address, assignigin 127.0.0.1...", "Domain resolve")
        targetIPaddress = "127.0.0.1"
else:
    printe("No target given, exiting...", "Target")
    terminate()

if not cliArg.nolog:
    if cliArg.logfile:
        logfile = cliArg.logfile

    else:
        if cliArg.domain:
            logfile = scriptpath + "log/check-" + targetDomain + "-"+ currentDateTime + ".log"
        else:
            logfile = scriptpath + "log/check-" + targetIPaddress + "-"+ currentDateTime + ".log"
        sys.stdout = Logger(logfile)

if cliArg.note:
    print g.PLUS + c.BOLD + "Note: %s" % cliArg.note + c.END
    print g.PIPE

targetIPrange = targetIPaddress.split(".")
targetIPrange = targetIPrange[0] + "." + targetIPrange[1] + "." + targetIPrange[2] + ".0"

if targetDomain == "Not defined":
    printh("Using IP address %s, no domain specified. Unable to run some modules." % targetIPaddress)
else:
    printh("Using IP address %s for domain %s" % (targetIPaddress, targetDomain))


if targetIPaddress != "127.0.0.1":
    iptype = IP(targetIPaddress).iptype()
else:
    iptype="PUBLIC"

if iptype == "PRIVATE" or iptype == "LOOPBACK":
    printh("IP address type is %s this may lead to errors." % iptype.lower())
else:
    "Fully Qualified Doman Name: " + socket.getfqdn(targetIPaddress) + c.END

### START MODULES

### GOOGLE SAFE BROWSING API LOOKUP
if (cliArg.googlesafebrowsing or cliArg.lists or cliArg.all) and targetDomain != "Not defined":
    try:
        GoogleAPIKey = os.environ['GAPIKEY']
        run.append("Google Safe Browsing")
        printh("Querying Google Safe Browsing API with domain name")
        target = 'http://' + targetDomain + '/'
        parameters = {'client': 'check-lookup-tool', 'key': GoogleAPIKey, 'appver': '1.0', 'pver': '3.1', 'url': target}
        reply = requests.get("https://sb-ssl.google.com/safebrowsing/api/lookup", params=parameters, headers=headers)
        if reply.status_code == 200:
            print g.PIPE + c.Y + "Status %s: Address http://%s/ found:" % (reply.status_code, targetDomain), reply.text + c.END
        elif reply.status_code == 204:
            print g.PIPE + c.G + "Status %s: The requested URL is legitimate." % (reply.status_code) + c.END
        elif reply.status_code == 400:
            printe("Status %s: Bad Request." % reply.status_code, "Google Safe Browsing")
        elif reply.status_code == 401:
            printe("Status %s: Not Authorized" % (reply.status_code), "Google Safe Browsing")
        elif reply.status_code == 503:
            printe("Status %s: Service Unavailable" % (reply.status_code), "Google Safe Browsing")
        else:
            printe("Status %s: Unhandled reply: " % (reply.status_code), "Google Safe Browsing")
        print g.PIPE
    except KeyError:
        printe("Google API key not present.", "Google Safe Browsing")

else:
    notRun.append("Google Safe Browsing")

### WEB OF TRUST API LOOKUP
if (cliArg.weboftrust or cliArg.lists or cliArg.all) and targetDomain != "Not defined":
    try:
        WOTAPIKey = os.environ['WOTAPIKEY'] ### same here.
        run.append("Web Of Trust")
        printh("Querying Web Of Trust reputation API with domain name")
        target = 'http://' + targetDomain + '/'
        parameters = {'hosts': targetDomain + "/", 'key': WOTAPIKey}
        reply = requests.get("http://api.mywot.com/0.4/public_link_json2", params=parameters, headers=headers)
        reply_dict = json.loads(reply.text)
        categories = {
        '101': c.R + 'Negative: Malware or viruses' + c.END,
        '102': c.R + 'Negative: Poor customer experience' + c.END,
        '103': c.R + 'Negative: Phishing' + c.END,
        '104': c.R + 'Negative: Scam' + c.END,
        '105': c.R + 'Negative: Potentially illegal' + c.END,
        '201': c.Y + 'Questionable: Misleading claims or unethical' + c.END,
        '202': c.Y + 'Questionable: Privacy risks' + c.END,
        '203': c.Y + 'Questionable: Suspicious' + c.END,
        '204': c.Y + 'Questionable: Hate, discrimination' + c.END,
        '205': c.Y + 'Questionable: Spam' + c.END,
        '206': c.Y + 'Questionable: Potentially unwanted programs' + c.END,
        '207': c.Y + 'Questionable: Ads / pop-ups' + c.END,
        '301': c.G + 'Neutral: Online tracking' + c.END,
        '302': c.G + 'Neutral: Alternative or controversial medicine' + c.END,
        '303': c.G + 'Neutral: Opinions, religion, politics ' + c.END,
        '304': c.G + 'Neutral: Other ' + c.END,
        '401': c.Y + 'Child safety: Adult content' + c.END,
        '402': c.Y + 'Child safety: Incindental nudity' + c.END,
        '403': c.R + 'Child safety: Gruesome or shocking' + c.END,
        '404': c.G + 'Child safety: Site for kids' + c.END,
        '501': c.G + 'Positive: Good site' + c.END}
        if reply.status_code == 200:
            hasKeys = False
            for key, value in reply_dict[targetDomain].iteritems():
                if key == "target":
                    print g.PLUS + "Server response OK, Web Of Trust Reputation Score for", c.BOLD + value + ":" + c.END
                elif key == "1":
                    () # Deprecated
                elif key == "2":
                    () # Deprecated
                elif key == "0" or key == "4":
                    hasKeys = True
                    if int(value[0]) >= 0:
                        assessment = c.R + "Very poor" + c.END
                    if int(value[0]) >= 20:
                        assessment = c.R + "Poor" + c.END
                    if int(value[0]) >= 40:
                        assessment = c.Y + "Unsatisfactory" + c.END
                    if int(value[0]) >= 60:
                        assessment = c.G + "Good" + c.END
                    if int(value[0]) >= 80:
                        assessment = c.G + "Excellent" + c.END
                    if key == "0":
                        print g.PIPE
                        print g.PIPE + "Trustworthiness:\t %s (%s) \t[%s%% confidence]" % (value[0], assessment, value[1])
                    elif key == "4":
                        print g.PIPE + "Child safety:\t %s (%s) \t[%s%% confidence]" % (value[0], assessment, value[1])
                elif key == "categories":
                    print g.PIPE
                    hasKeys = True
                    for e,s in value.iteritems():
                        print g.PIPE + "Category:\t %s \t[%s%% confidence]" % (categories[e], s)
                    print g.PIPE
                elif key == "blacklists":
                    hasKeys = True
                    for e,s in value.iteritems():
                        print g.PIPE + "Blacklisted:\t %s \tID: %s" % (e, s)
                else:
                    print "Unknown key", key, " => ", value
        if hasKeys == False:
            print g.PIPE + c.G + "Web Of Trust has no records for", targetDomain + c.END
            print g.PIPE
        if reply.status_code != 200:
            printe("Server returned status code %s see https://www.mywot.com/wiki/API for details." % reply.status_code, "Web Of Trust")
    except KeyError:
        printe("Web Of Trust API key not present.", "Web Of Trust")
else:
    notRun.append("Web Of Trust")

### BLACKLISTS
if cliArg.blacklists or cliArg.lists or cliArg.all:
    run.append("Blacklists")
    removed = trimcache(72) # Delete entries older than 72h
    print g.STAR + c.B + "Cache trim: %s MB removed, current cache size %s MB." % removed + c.END
    totalLines = 0
    if os.path.isfile(blacklistSourceFile) == True:
        with open(blacklistSourceFile) as sourcefile:
            sourceListLine = sourcefile.readlines()
            sourceCount = 0
    else:
        printe("No blacklist file found at %s" % blacklistSourceFile, "blacklist")
        sourceListLine = ""
        cachefilew = open(os.devnull, "w+")
        cachefiler = open(os.devnull, "r+")

    for line in sourceListLine:
        if line[:1] == "#":
            continue
        else:
            sourceCount += 1
    printh("Downloading and searching blacklists for address.")
    i = 0
    cacherefreshcount = 0
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
        print g.PLUS + "Downloading from " + c.BOLD + sourcename + c.END + " [%s of %s sources]:" % (i, sourceCount) + c.END

        try:
            data = ""
            head = requests.head(sourceurl, headers=headers)
        except Exception:
            print g.PIPE + "[" + c.R + "Fail!" + c.END + "] Unable to connect to %s" % (sourcename)
            continue

        try:
            timestamp = head.headers['Last-Modified']
        except KeyError:
            timestamp = "1970-01-02 00:00:00"

        eStamp = int(time.mktime(dateutil.parser.parse(timestamp).timetuple()))
        agediff = eNow - eStamp
        filehash = hashlib.md5(sourceurl.encode('utf-8')).hexdigest()
        cachepath = scriptpath + "cache/" + str(eStamp) + "-" + filehash
        if eStamp == 79200:
            usecache = False
        else:
            usecache = os.path.isfile(cachepath)
        if usecache == True:
            if agediff >= 60:
                age = "%s%s%s minutes ago" % (c.G, (agediff / 60), c.END)

            if agediff >= 3600:
                age = "%s%s%s hours ago" % (c.G, (agediff / 3600), c.END)

            if agediff >= 86400:
                if (agediff / 86400) >= 14:
                    age = "%s%s%s days ago, %sstale source?%s" %(c.R, (agediff / 86400), c.END, c.R, c.END)
                else:
                    age = "%s%s%s days ago" % (c.Y, (agediff / 86400), c.END)
            print g.PIPE + "[" + c.B + "Cache" + c.END + "] Using a cached copy. Source updated %s." % age
            cachefiler = open(cachepath, "r+")
            cachefilew = open(os.devnull, "w+")
        else:
            cachefilew = open(cachepath, "w+")
            cachefiler = open(os.devnull, "r+")
            cachefilew.truncate()
        if usecache == True:
            lines = cachefiler.readlines()
            for line in lines:
                linecount += 1
            print  g.PIPE + "Searching from %s lines." % (linecount) + c.END
            totalLines = totalLines + (linecount - 1)
            req = None
            for line in lines:
                if targetDomain != "Not defined":
                    if targetDomain in line:
                        domainmatch = True
                        print g.PIPE + c.Y + "Domain match! " + c.END + line.replace(targetDomain, c.R + targetDomain + c.END).replace("\n", "")
                if targetIPaddress in line:
                    ipmatch = True
                    print g.PIPE + c.Y + "IP match! " + c.END + line.replace(targetIPaddress, c.R + targetIPaddress + c.END).replace("\n", "")
                if targetIPrange in line:
                    ipmatch = True
                    print g.PIPE + c.Y + "Range match! " + c.END + line.replace(targetIPrange, c.R + targetIPrange + c.END).replace("\n", "")
            if domainmatch == False and ipmatch == True and targetDomain != "Not defined":
                print g.PIPE + "Domain name not found." + c.END
            elif ipmatch == False and domainmatch == True:
                print g.PIPE + "IP address not found." + c.END
            else:
                print g.PIPE + "Address "+ c.G + "not found" + c.END + " in list." + c.END

        if usecache == False:
            cacherefreshcount += 1
            req = requests.get(sourceurl, stream=True, headers=headers)
            try:
                cd = req.headers['Content-Disposition']
            except Exception:
                cd = ""
            filesize = req.headers.get('content-length')
            if not filesize:
                # Assuming no content-length header or content-type
                sys.stdout.write(g.PIPE + "[" + c.G + "Done!" + c.END + "] Content-length not received. " + cd + c.END)
                data = req.content
                cType = "text/plain"
            else:
                cType = req.headers.get('content-type')
                if not cType:
                    cType = "text/plain"
                sys.stdout.write(g.PIPE + "[" + c.R + "     " + c.END + "] Filesize: " + str(int(filesize) / 1024) + " kb \tContent type: " + str(cType) + " \r" + g.PIPE + "[")
                part = int(filesize) / 5
                count = 0
                for chunk in req.iter_content(part):
                    count += 1
                    if count <= 5:
                        if count == 1:
                            sys.stdout.write(c.G + "D" + c.END)
                        if count == 2:
                            sys.stdout.write(c.G + "o" + c.END)
                        if count == 3:
                            sys.stdout.write(c.G + "n" + c.END)
                        if count == 4:
                            sys.stdout.write(c.G + "e" + c.END)
                        if count == 5:
                            sys.stdout.write(c.G + "!" + c.END)
                        sys.stdout.flush()
                    data = data + chunk
                while count < 5: # Fill the meter if the chunks round down.
                    count += 1
                    sys.stdout.write(c.G + "!" + c.END)
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
                sys.stdout.write("\r\n" + g.PIPE + "Decompressing and using largest file in archive: %s (%s bytes)." % (largestfile, largestsize))
                file = zip_file_object.open(largestfile)
                listfile = file.read()
            else:
                listfile = data
            cachefilew.write("Cached copy for %s\n" % cachepath)
            for line in listfile.splitlines():
                cachefilew.write(line.replace("\n", ""))
                cachefilew.write("\r\n")
                linecount += 1
            print "\r\n" + g.PIPE + "Searching from %s lines." % (linecount) + c.END
            totalLines = totalLines + linecount
            for line in listfile.splitlines():
                if targetDomain != "Not defined":
                    if targetDomain in line:
                        domainmatch = True
                        print g.PIPE + c.Y + "Domain match! " + c.END + line.replace(targetDomain, c.R + targetDomain + c.END).replace("\n", "")
                if targetIPaddress in line:
                    ipmatch = True
                    print g.PIPE + c.Y + "IP match! " + c.END + line.replace(targetIPaddress, c.R + targetIPaddress + c.END).replace("\n", "")
                if targetIPrange in line:
                    ipmatch = True
                    print g.PIPE + c.Y + "Range match! " + c.END + line.replace(targetIPrange, c.R + targetIPrange + c.END).replace("\n", "")
            if domainmatch == False and ipmatch == True and targetDomain != "Not defined":
                print g.PIPE + "Domain name not found." + c.END
            elif ipmatch == False and domainmatch == True:
                print g.PIPE + "IP address not found." + c.END
            else:
                print g.PIPE + "Address "+ c.G + "not found" + c.END + " in list." + c.END

          #except Exception:
              #printe("Failed: %s %s " % (str(sys.exc_info()[0]), str(sys.exc_info()[1])), "blacklist")
              #runerrors = True

    cachefiler.close()
    cachefilew.close()
    print g.PLUS + "A total of %s lines searched, %s cached files updated." % (totalLines, cacherefreshcount) + c.END
    print g.PIPE
else:
    notRun.append("Blacklists")

### SPAMLISTS
if cliArg.spamlists or cliArg.lists or cliArg.all:
    run.append("Spamlists")
    printh("Querying spamlists for %s..." % targetIPaddress)
    for bl in sourceListSpamDNS:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(targetIPaddress).split("."))) + "." + bl
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            print g.PIPE + c.Y + 'IP: %s IS listed in %s (%s: %s)' %(targetIPaddress, bl, answers[0], answer_txt[0]) + c.END
        except dns.resolver.NXDOMAIN:
            print g.PIPE + 'IP: %s is NOT listed in %s' %(targetIPaddress, bl)
    print g.PIPE
else:
    notRun.append("Spamlists")

### VIRUSTOTAL

if cliArg.virustotal or cliArg.lists or cliArg.all:
    try:
        VirusTotalAPIKey = os.environ['VTAPIKEY'] ### Export your api keys to shell variables or put them here, add "Export VTAPIKEY=yourapikey to .bashrc or whatever your using."
        run.append("VirusTotal")
        printh("Querying VirusTotal for %s..." % targetIPaddress)
        parameters = {
            'ip': targetIPaddress,
            'apikey': VirusTotalAPIKey
                    }
        vtresponse = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report', params=parameters).content
        vtresponse_dict = json.loads(vtresponse)
        if vtresponse_dict['response_code'] == 0:
            print g.STAR + c.Y + "VirusTotal response: IP address not in dataset." + c.END
        else:
            print g.PLUS + c.G + "VirusTotal response code", vtresponse_dict['response_code'], vtresponse_dict['verbose_msg'] + c.END
            for entry in vtresponse_dict['resolutions']:
                print g.PIPE + " =>", entry['hostname'], "Last resolved:", entry['last_resolved']
            print g.PIPE
            if len(vtresponse_dict['detected_urls']) >= 1:
                print c.G + g.PLUS + "Detections in this address:" + c.END
                for entry in vtresponse_dict['detected_urls']:
                    print g.PIPE + entry['url'].replace("http", "hxxp") + c.END
                    if entry['positives'] >= 1:
                        print g.PIPE + "Positives: ", c.R + str(entry['positives']) + c.END, "\tTotal:", entry['total'], "\tScan date:", entry['scan_date']
                    else:
                        print g.PIPE + "Positives: ", entry['positives'], "\tTotal:", entry['total'], "\tScan date:", entry['scan_date']
                    print g.PIPE
    except KeyError:
        printe("VirusTotal API key not present.", "VirusTotal")


else:
    notRun.append("VirusTotal")

### PASSIVETOTAL
if cliArg.passivetotal or cliArg.lists or cliArg.all:
    try:
        PassiveTotalAPIKey = os.environ['PTAPIKEY'] ### same here.
        run.append("PassiveTotal")
        #disable passivetotal's error message
        requests.packages.urllib3.disable_warnings()
        #define API key
        pt = PassiveTotal(PassiveTotalAPIKey)
        printh("Querying PassiveTotal for %s..." % targetIPaddress)
        try:
            response = ""
            response = pt.get_passive(targetIPaddress)
        except ValueError:
            printe("Value error - no data received.", "PassiveTotal")
        if response == "":
            g.FAIL + c.R + "Empty response, maybe your over your quota?"
        elif response['success']:
            print g.PIPE + "Query:", response['raw_query']
            print g.PIPE + "First Seen:", response['results']['first_seen']
            print g.PIPE + "Last Seen:", response['results']['last_seen']
            print g.PIPE + "Resolve Count: ", response['result_count']
            print g.PIPE + "Resolutions"
            response = response['results']
            for resolve in response['records']:
                print g.PIPE + "==> ", resolve['resolve'], "\t", resolve['firstSeen'], "\t", resolve['lastSeen'], "\t", ', '.join([ str(x) for x in resolve['source'] ])
        else:
            printe("%s" % response['error'], "PassiveTotal")
        print g.PIPE

    except KeyError:
        printe("PassiveTotal API key not present.", "PassiveTotal")
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
            printh("Querying GeoIP database for %s" % targetIPaddress)
            if gir is None:
                printe("No geodata found for IP address.", "GeoIP")
            else:
                for key, value in gir.iteritems():
                    if key == "latitude":
                        latitude = value
                    elif key == "longitude":
                        longitude = value
                    print g.PIPE + str(key) + ": " + str(value)
                if latitude != "" and longitude != "":
                    print g.PIPE + "Google maps link for location: " + c.UL + "https://maps.google.com/maps?q="+str(latitude)+","+str(longitude) + c.END
                if cliArg.openlink:
                    webbrowser.open('https://maps.google.com/maps?q='+str(latitude)+','+str(longitude))
        except Exception:
            printe("Failed: %s %s " % (str(sys.exc_info()[0]), str(sys.exc_info()[1])), "GeoIP")
    else:
        printe("Database not found at %s" % GeoIPDatabaseFile, "GeoIP")
        printe("Please install GeoIP database. http://dev.maxmind.com/geoip/legacy/install/city/", "")
    print g.PIPE
else:
    notRun.append("GeoIP")

### WHOIS
if cliArg.whois or cliArg.lists or cliArg.all:
    run.append("Whois")
    results = results2 = ""
    try:
        results = subprocess.check_output("whois "+targetIPaddress, shell=True)
    except subprocess.CalledProcessError:
        printe("Whois returned an error.", "Whois")
    if targetDomain != "Not defined":
        try:
            results2 = subprocess.check_output("whois "+targetDomain, shell=True)
        except subprocess.CalledProcessError:
            printe("Whois returned an error.", "Whois")
    if results:
        printh("Querying IP Address %s" % targetIPaddress)
        for line in results.splitlines():
            if ("abuse" in line and "@" in line) or "address" in line or "person" in line or "phone" in line:
                print g.PIPE + c.BOLD + c.B + line + c.END
            elif "descr" in line:
                print g.PIPE + c.BOLD + c.Y + line + c.END
            else:
                print g.PIPE + line  + c.END
    if results2:
        print c.HDR +  g.PLUS + "Resolved address " + targetIPaddress + " for domain " + targetDomain + c.END
        for line in results2.splitlines():
            if "#" in line:
                ()
            elif ("abuse" in line and "@" in line) or "address" in line or "person" in line or "phone" in line:
                print g.PIPE + c.BOLD + c.B + line + c.END
            elif "descr" in line:
                print g.PIPE + c.BOLD + c.Y + line + c.END
            else:
                print g.PIPE + line  + c.END
        print g.PIPE
else:
    notRun.append("Whois")

#### PING
if cliArg.ping or cliArg.probes or cliArg.all:
    run.append("Ping")
    printh("Pinging %s, skip with CTRL-C..." % targetIPaddress)
    try:
        response = os.system("ping -c 1 " + targetIPaddress + " > /dev/null 2>&1")
        if response == 0:
            print g.PIPE + c.G + targetIPaddress, 'is responding to ping.' + c.END
        else:
            print g.PIPE + c.R + targetIPaddress, 'is not responding to ping.' + c.END
            print g.PIPE + c.END
    except KeyboardInterrupt:
        print c.Y + g.MINUS + "Skipping ping." + c.END
        notRun.append("Ping")
    print g.PIPE
else:
    notRun.append("Ping")

### OPENSSL
if cliArg.cert or cliArg.probes or cliArg.all:
    run.append("OpenSSL")
    results = None
    try:
        results = subprocess.check_output("echo | openssl s_client -showcerts -servername %s -connect %s:443 2>/dev/null | openssl x509 -inform pem -noout -text" % (targetDomain, targetDomain), shell=True)
    except subprocess.CalledProcessError:
        printe("OpenSSL returned an error.", "OpenSSL")
    if results:
        printh("Certificate information for https://%s/" % targetDomain)
        for line in results.splitlines():
            if "Issuer" in line or "Subject:" in line or "DNS:" in line or "Not Before" in line or "Not After" in line:
                print g.PIPE + c.B + line.replace("  ", " ") + c.END
            else:
                print g.PIPE + line.replace("  ", " ") + c.END
else:
    notRun.append("OpenSSL")

### SCANPORTS & SCANHEADERS
if cliArg.scanports or cliArg.scanheaders or cliArg.probes or cliArg.all:
    run.append("Portscan")
    printh("Scanning common ports...")
    socket.setdefaulttimeout(1)
    openports = []
    try:
        for port in targetPortscan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((targetIPaddress, port))
            if result == 0:
                print g.PIPE + c.G + "port " + str(port) + " is open." + c.END
                openports.append(port)
            else:
                print g.PIPE + "Port %s is closed." % port
            sock.close()

        if (cliArg.scanheaders or cliArg.probes or cliArg.all) and targetDomain != "Not defined":
            for port in openports:
                url = "http://" + targetDomain
                try:
                    if port == 443:
                        protocol = "https://"
                    else:
                        protocol = "http://"
                    print g.PIPE
                    print g.PLUS + "Getting headers for %s%s:%s" % (protocol, targetDomain, port) + c.END
                    page = requests.head('%s%s:%s' % (protocol, targetDomain, port), headers={'user-agent': random.choice(uapool), 'referer': 'https://www.google.com'})
                    print g.PIPE + c.BOLD + "Server response code: %s" % page.status_code + c.END
                    for key, value in page.headers.items():
                        print g.PIPE + c.BOLD + "%s: %s" % (key, value) + c.END
                except Exception,e:
                    printe(str(e), "Headerscan")

    except KeyboardInterrupt:
        print c.R + g.STAR + "Caught Ctrl+C, interrupting..."
        sys.terminate()
    except socket.gaierror:
        print c.R + g.STAR + "Hostname could not be resolved. Exiting..."
        sys.terminate()
    except socket.error:
        print c.R + g.STAR + "Couldn't connect to server."
        sys.terminate()
    print g.PIPE + c.END
else:
    notRun.append("Portscan")
if logfile != "":
    printh("Writing log file to %s" % logfile)

terminate()
