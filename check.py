# -*- coding: utf-8 -*-
# pip install IPy TwitterSearch python-dateutil dnspython
#
# If you get InsecurePlatformWarnings from urllib3, fix this by installing the pip package requests[security]
#
# See https://github.com/AnttiKurittu/check/ for more details.

import datetime

startTime = datetime.datetime.now()

import os
import sys
import socket
import json
import argparse
import webbrowser
import subprocess
import zipfile
import dns.resolver
import requests
import StringIO
import operator
import random
import hashlib
import dateutil.parser
import time
import zlib
import gzip
from TwitterSearch import *
from base64 import b64decode
from IPy import IP

parser = argparse.ArgumentParser(description='Get actions')
parser.add_argument("-d",
                    "--domain",
                    metavar='domain name',
                    type=str,
                    help="Target domain name")
parser.add_argument("-i",
                    "--ip",
                    metavar='IP address',
                    type=str,
                    help="Target IP address")
parser.add_argument("-a",
                    "--all",
                    help="run all queries",
                    action="store_true")
parser.add_argument("-l",
                    "--lists",
                    help="run all third-party lists for matches",
                    action="store_true")
parser.add_argument("-p",
                    "--probes",
                    help="run all host-contacting probes",
                    action="store_true")
parser.add_argument("-pg",
                    "--ping",
                    help="Ping address",
                    action="store_true")
parser.add_argument("-ws",
                    "--whois",
                    help="Query WHOIS information",
                    action="store_true")
parser.add_argument("-cr",
                    "--cert",
                    help="Display certificate information via OpenSSL",
                    action="store_true")
parser.add_argument("-sp",
                    "--scanports",
                    help="Scan common ports",
                    action="store_true")
parser.add_argument("-sh",
                    "--scanheaders",
                    help="Scan common ports and try to retrieve headers",
                    action="store_true")
parser.add_argument("-ms",
                    "--metascan",
                    help="Query Metscan Online for detections",
                    action="store_true")
parser.add_argument("-gs",
                    "--googlesafebrowsing",
                    help="Query Google Safe Browsing database",
                    action="store_true")
parser.add_argument("-wt",
                    "--weboftrust",
                    help="Query Web Of Trust reputation database",
                    action="store_true")
parser.add_argument("-sl",
                    "--spamlists",
                    help="Check a number of spam resolvers for IP",
                    action="store_true")
parser.add_argument("-bl",
                    "--blacklists",
                    help="Check local and third-party blacklists for matches",
                    action="store_true")
parser.add_argument("-vt",
                    "--virustotal",
                    help="Query passive DNS and detection records from VirusTotal",
                    action="store_true")
parser.add_argument("-tw",
                    "--twitter",
                    help="Search Twitter for recent mentions of Domain or IP",
                    action="store_true")

parser.add_argument("-nt",
                    "--note",
                    metavar='note',
                    type=str,
                    help="Add a note to the output, \
this could be a project name or description of address.")
parser.add_argument("-O",
                    "--openlink",
                    help="Open GeoIP location in Google Maps",
                    action="store_true")
parser.add_argument("-L",
                    "--logfile",
                    type=str,help="Specify a log file, default is ./log/check\
-[IP]-[DATETIME].log")
parser.add_argument("-NL",
                    "--nolog",
                    help="Do not write log",
                    action="store_true")
parser.add_argument("-M", "--monochrome",
                    help="Suppress colors",
                    action="store_true")
parser.add_argument("-NG", "--nogfx",
                    help="Suppress line graphics",
                    action="store_true")
parser.add_argument("-S", "--nosplash",
                    help="Suppress cool ASCII header graphic",
                    action="store_true")
parser.add_argument("-P", "--pause",
                    help="Pause between modules",
                    action="store_true")


arg = parser.parse_args()

if arg.lists is True or arg.all is True:
    arg.googlesafebrowsing = True
    arg.weboftrust = True
    arg.virustotal = True
    arg.blacklists = True
    arg.spamlists = True
    arg.twitter = True
    arg.metascan = True

if arg.probes is True or arg.all is True:
    arg.cert = True
    arg.ping = True
    arg.scanheaders = True
    arg.scanports = True

if arg.all is True:
    arg.whois = True

splash = zlib.decompress(b64decode("eJxtkNENgDAIRP87xf364y3gIiYkLMLwQhEtxktJKUc\
ebYeWsHu49EdRRerj7BFDNB2IARa7Viu7lyApbGRR9RgMvPjibPTUcuCm6B7zbHUhEgWRWQt+nE/MqS\
npHg48ECtDJ+S9H7OZzz+weeavAiWefEN5f5BDaizXrWWLtxSXjgvlm2ST"))

# Specify resources and API keys
ownPath = os.path.dirname(sys.argv[0]) + "/"
if ownPath is "/" or ownPath is "":
    ownPath = "./"
curDate = str(datetime.datetime.now().strftime("%Y-%m-%d-%H:%M"))
eNow = int(time.mktime(dateutil.parser.parse(curDate).timetuple()))

# Specify database file location
targetPortscan = [80, 443, 8000, 20, 21, 22, 23, 25, 53]  # What ports to scan
blacklistSourceFile = ownPath + "blacklists.txt"
sourceListSpamDNS = [
    "zen.spamhaus.org",
    "spam.abuse.ch",
    "cbl.abuseat.org",
    "virbl.dnsbl.bit.nl",
    "dnsbl.inps.de",
    "ix.dnsbl.manitu.net",
    "dnsbl.sorbs.net",
    "bl.spamcannibal.org",
    "bl.spamcop.net",
    "xbl.spamhaus.org",
    "pbl.spamhaus.org",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "db.wpbl.info"
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
headers = {'user-agent': 'Mozilla/5.0 (Check.py extended address information lookup tool)',
           'referer': 'https://www.github.com/AnttiKurittu/check'}
hasError = []  # Gather erring modules
logfile = None  # Set variable as blank to avoid errors further on.
notRun = []  # Gather skipped modules
run = []  # Gather executed modules
missingkeys = []

if arg.monochrome:
    class c:

        D = HDR = B = G = Y = R = END = BOLD = UL = ''
else:
    class c:
        HDR = '\033[96m'
        B = '\033[94m'
        Y = '\033[93m'
        G = '\033[92m'
        R = '\033[91m'
        D = '\033[90m'
        END = '\033[0m'
        BOLD = '\033[1m'
        UL = '\033[4m'

if arg.nogfx:
    class g:
        STAR = PLUS = PIPE = FAIL = MINUS = ''
else:
    class g:
        STAR = c.D + "[" + c.G + "*" + c.D + "] " + c.END
        PLUS = c.D + "[" + c.END + c.BOLD + "+" + c.D + "] " + c.END
        PIPE = c.D + " |  " + c.END
        FAIL = c.D + "[" + c.R + "!" + c.D + "] " + c.END
        MINUS = c.D + "[-] " + c.END


class Logger(object):  # Log output to file, remove colors.
    def __init__(self, filename=logfile):
        self.terminal = sys.stdout
        self.log = open(filename, "w")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message.replace("\033[95m", "")
                       .replace("\033[94m", "").replace("\033[93m", "")
                       .replace("\033[92m", "").replace("\033[91m", "")
                       .replace("\033[0m", "").replace("\033[1m", "")
                       .replace("\033[4m", "").replace("\033[90m", "")
                       .replace("\033[96m", ""))

    def flush(self):
        self.terminal.flush()

def terminate():  # Graceful exit.
    global missingkeys
    stopTime = datetime.datetime.now()
    totalTime = stopTime - startTime
    if len(hasError) > 0:
        printh(
            "Executed %s modules with errors in %s, runtime %s seconds." %
            (len(run), ", ".join(hasError), totalTime.seconds))
    else:
        printh(
            "Executed %s modules in %s seconds." %
            (len(run), totalTime.seconds))
    printh("Skipped %s modules." % len(notRun))
    if len(missingkeys) >0:
        printh("No API keys configured for: %s" % (str(", ".join(missingkeys))))
    exit()

# Removes cache files older than h, returns removed megabyte amount.
def trimcache(h):
    filelist = [f for f in os.listdir(ownPath + "cache")]
    removedSize = 0
    cacheSize = 0
    removeCount = 0
    for f in filelist:
        filesize = os.path.getsize(ownPath + "cache/" + f)
        cacheSize = cacheSize + filesize
        filedate = 0
        difference = 0
        if len(f) == 43:
            filedate = f.split("-")
            filedate = int(filedate[0])
            difference = (eNow - filedate) / 8600
            if difference >= h:
                removedSize = removedSize + filesize
                removeCount += 1
                os.remove(ownPath + "cache/" + f)
    megabytesRemoved = removedSize / 1000000
    megabytesLeft = (cacheSize - removedSize) / 1000000
    return removeCount, megabytesRemoved, megabytesLeft

def printe(message, module):
    if module != "":
        print g.FAIL + c.R + ("%s: %s" % (module, message)) + c.END
        hasError.append(module)
    else:
        print g.FAIL + c.R + ("%s" % message) + c.END

def printh(message):
    print g.STAR + c.HDR + message + c.END

def printp(message):
    print g.PLUS + c.END + message

def printl(message, color = ""):
    print g.PIPE + color + message + c.END

def pipe():
    print c.D + g.PIPE + c.END

def validate_ip(ip):  # Validate IP address format
    try:
        socket.inet_aton(ip)
    except Exception:
        return False
    return True


def matchfinder(f):
    out = []
    dm = ipm = rm = False
    for line in f:
        if Domain != "" and Domain in line:
            dm = True
            out.append(
                c.Y + "Domain match! " + c.END + line.replace(Domain, c.R + Domain + c.END).replace("\n", ""))
            matchcollector.append(line)
        if IPaddr != "" and IPaddr in line:
            ipm = True
            out.append(
                c.Y + "IP match! " + c.END + line.replace(IPaddr, c.R + IPaddr + c.END).replace("\n", ""))
            matchcollector.append(line)
        if iIPr != "" and iIPr in line:
            ipm = True
            out.append(
                c.Y + "Range match! " + c.END + line.replace(iIPr, c.R + iIPr + c.END).replace("\n", ""))
            matchcollector.append(line)
    if dm == False and ipm == True and Domain != "":
        out.append(g.PIPE + "Domain name not found." + c.END)
    elif ipm == False and dm == True:
        out.append("IP address not found." + c.END)
    else:
        out.append("Address " + c.G + "not found" + c.END + " in list." + c.END)
    return out

def pause():
    a = raw_input(" *  Press [ENTER] to continue...")
    a = ""

# Read or create configuration file
if os.path.isfile(ownPath + "apikeys.conf"):
    settings = {}
    with open(ownPath + "apikeys.conf", "r+") as f:
        for line in f:
            if line[0] == "#":
                continue
            if ":" in line:
                (key, val) = line.split(":")
                settings[key.strip()] = val.strip()
        f.close()
    if settings['WebOfTrustAPIKey'] is "":
        missingkeys.append("Web Of Trust")
        arg.weboftrust = False
    if settings['VirusTotalAPIKey'] is "":
        missingkeys.append("VirusTotal")
        arg.virustotal = False
    if settings['MetaScanAPIKey'] is "":
        missingkeys.append("MetaScan")
        arg.metascan = False
    if settings['GoogleAPIKey'] is "":
        missingkeys.append("Google")
        arg.googlesafebrowsing = False
    if settings['TwitterConsumerKey'] is ""\
            or settings['TwitterConsumerSecret'] is ""\
            or settings['TwitterAccessToken'] is ""\
            or settings['TwitterAccessTokenSecret'] is "":
        missingkeys.append("Twitter")
        arg.twitter = False

else: # If no configuration file present, create one.
    printe("No API key configuration file found, writing a template to %sapikeys.conf." % ownPath, "Configuration")
    f = open(ownPath + "apikeys.conf", "w")
    f.write(zlib.decompress(b64decode("eJxtj8FqwzAQRO/+ioXc/QG9hRxKKaWGhIQeZXlsL1Yko103+O+7bqtAIBfBvJllRjs6jPBTPa+0b95o\
wko+xZ6HJTvlFKnngKraURPgBOS6jta05JIW0kQ6svwGa/pKC3kXKbXqOJILwVzY4T3fp0x9BuxJ183kTBkywyt/g25ohRVC7Wp4YFFkjkNtEy6sI51urIa\
2ERSBbusvObJiN8+B/d92FzsaoFvJY7+OTuuquqD97E95ETX3HetLdWZTp6QuFPIBdUf7UdGvKQ0BRTVOxFY/XPwvPKQoyxX5GTvCZ+gd772HWO2E+IyV9A\
8JWZfF"
                                      )))
    settings = {
                'WebOfTrustAPIKey': None,
                'VirusTotalAPIKey': None,
                'GoogleAPIKey': None,
                'MetaScanAPIKey': None,
                'TwitterConsumerKey': None,
                'TwitterConsumerSecret': None,
                'TwitterAccessToken': None,
                'TwitterAccessTokenSecret': None,
                }
    arg.twitter = arg.passivetotal = arg.weboftrust = arg.virustotal = arg.metascan = arg.googlesafebrowsing = False
    f.close()

if arg.ip and arg.domain:
    printe("Specify an IP address or domain, not both! Exiting...", "Dual target")
    terminate()

if arg.ip:
    if validate_ip(arg.ip) == False:
        printe("Invalid IP address, exiting...", "Validate IP")
        terminate()
    else:
        IPaddr = arg.ip
        Domain = ""

elif arg.domain:
    Domain = arg.domain.replace("https://", "").replace("http://", "")
    Domain = Domain.split("/")[0]
    try:
        my_resolver = dns.resolver.Resolver()
        my_resolver.nameservers = ['8.8.8.8']
        answers = my_resolver.query(Domain, 'A')

        printh(
            "%s IP addresses returned, using first A record %s for %s." % (len(answers), answers[0], Domain))
        IPaddr = str(answers[0])
    except dns.resolver.NXDOMAIN:
        printe("No A records returned from public DNS %s." %
               my_resolver.nameservers, "Domain resolve / Public")
    try:
        IPaddrLocal = socket.gethostbyname(Domain)
        if IPaddrLocal != IPaddr:
            printh(
                "Public DNS reports different results (%s) from host DNS results (%s)" %
                (IPaddr, IPaddrLocal))
    except socket.gaierror:
        printe(
            "Resolving domain %s failed." %
            Domain, "Domain resolve / Local")
        IPaddr = ""

else:
    printe("No target given, exiting...", "Target")
    terminate()

if not arg.nolog:
    if arg.logfile:
        logfile = arg.logfile
    else:
        if arg.domain:
            logfile = ownPath + "log/check-" + Domain + "-" + curDate + ".log"
        else:
            logfile = ownPath + "log/check-" + IPaddr + "-" + curDate + ".log"
        sys.stdout = Logger(logfile)

if not arg.nosplash:
    print splash
    print "\nCheck.py - Extended lookup tool. See -h for command line options.\n"


if arg.note:
    printl("Note: %s" % arg.note)
    pipe()

if IPaddr != "":
    iIPr = IPaddr.split(".")
    iIPr = iIPr[0] + "." + iIPr[1] + "." + iIPr[2] + ".0"
else:
    iIPr = ""

if Domain == "":
    printh("Using IP address %s, no domain specified. Unable to run some modules." %
        IPaddr)

if IPaddr != "":
    iptype = IP(IPaddr).iptype()
else:
    iptype = "PUBLIC"
if iptype == "PRIVATE" or iptype == "LOOPBACK":
    printh("IP address type is %s this may lead to errors." % iptype.lower(), "IP Type")
else:
    "Fully Qualified Doman Name: " + socket.getfqdn(IPaddr) + c.END

# VIEW LOCAL RESOLVE HISTORY
if os.path.isfile(ownPath + "resolvehistory.log"):
    f = open(ownPath + "resolvehistory.log", "r+")
    h = f.read()
    i = 0

    if (Domain in h or IPaddr in h) and (Domain != ""):
        printh("Latest three resolvations for address in local history:")
        for line in reversed(h.splitlines()):
            if (Domain in line or IPaddr in line) and i <= 2:
                i += 1
                printl(line, c.G)
        if arg.pause:
            pause()
    f.close()

# ADD resolve results
if Domain != "":
    f = open(ownPath + "resolvehistory.log", "a+")
    if IPaddr == "":
        history = ["Failed", curDate, Domain, IPaddr]
    elif IPaddrLocal != IPaddr:
        history = ["Resolved", curDate, Domain, IPaddr, "Local:", IPaddrLocal]
    else:
        history = ["Resolved", Domain, IPaddr, curDate]
    f.write(", ".join(history))
    f.write("\n")
    f.close()

# TWITTER
if arg.twitter:
    run.append("Twitter")
    try:
        tso = TwitterSearchOrder() # create a TwitterSearchOrder object
        keyword_domain = "\"" + Domain + "\""
        keyword_ip = "\"" + IPaddr + "\""
        if Domain == "" and IPaddr != "":
            tso.set_keywords([ keyword_ip ], or_operator = True)
            keywords_desc = "IP address"
        elif Domain != "" and IPaddr == "":
            tso.set_keywords([ keyword_domain ], or_operator = True)
            keywords_desc = "domain name"
        else:
            tso.set_keywords([ keyword_domain, keyword_ip ], or_operator = True)
            keywords_desc = "IP address or domain name"

        printh("Querying Twitter for tweets mentioning %s..." % keywords_desc)
        #tso.set_language('en')
        tso.set_include_entities(False)
        tso.remove_all_filters()
        ts = TwitterSearch(
            consumer_key = settings['TwitterConsumerKey'],
            consumer_secret = settings['TwitterConsumerSecret'],
            access_token = settings['TwitterAccessToken'],
            access_token_secret = settings['TwitterAccessTokenSecret']
         )
        i = 0
        for tweet in ts.search_tweets_iterable(tso):
            if i < 100:
                printl("[%s%s%s] %s@%s%s%s%s:" % (c.Y, tweet['created_at'], c.END, c.G, c.END,
                                                          c.BOLD, tweet['user']['screen_name'].encode('utf8'), c.END
                                              ))
                printl("%s" % (tweet['text'].encode('utf8').replace("\n", "%s/%s " % (c.R, c.END))))
                try:
                    printl("\t%s=> Expanded URL:%s %s" % (c.G, c.END, tweet['user']['entities']['url']['urls'][0]['expanded_url'].encode('utf8')
                                                                              .replace(Domain, c.R + Domain + c.END).replace(IPaddr, c.R + Domain + c.END)))
                except KeyError:
                    ()
                except AttributeError:
                    ()
                except IndexError:
                    () # Do nothing.
                i += 1
            else:
                printp(("Showing %s/100 results." % ts.get_amount_of_tweets()))
                break
        if i == 0:
            printp("No tweets found.")
    except TwitterSearchException as e:
        printe(e)
    if arg.pause:
        pause()
else:
    notRun.append("Twitter")

# PING
if arg.ping and IPaddr != "":
    run.append("Ping")
    printh("Pinging %s, skip with CTRL-C..." % IPaddr)
    try:
        response = os.system("ping -c 1 " + IPaddr + " > /dev/null 2>&1")
        if response == 0:
            printl("%s is responding to ping." % (IPaddr), c.G)
        else:
            printl("%s is not responding to ping." % (IPaddr), c.Y)
    except KeyboardInterrupt:
        printl("Skipping ping.", c.R)
        notRun.append("Ping")
    pipe()
    if arg.pause:
        pause()
else:
    notRun.append("Ping")

# METASCAN API LOOKUP
if arg.metascan:
    postdata_desc = postdata = ""
    run.append("Metascan")
    headers={'apikey': settings['MetaScanAPIKey']}
    if Domain == "":
        postdata =  str({'address': [IPaddr]}).replace(" ", "").replace("\'", "\"")
        postdata_desc = "IP address"
    if IPaddr == "":
        postdata =  str({'address': [Domain]}).replace(" ", "").replace("\'", "\"")
        postdata_desc = "Domain name"
    if Domain != "" and IPaddr != "":
        postdata =  str({'address': [IPaddr, Domain]}).replace(" ", "").replace("\'", "\"")
        postdata_desc = "IP address and domain name"
    printh("Querying Metascan Online with %s." % postdata_desc)
    reply = requests.post(
        "https://ipscan.metascan-online.com/v1/scan", data=postdata, headers=headers)

    if reply.status_code != 200:
        if reply.status_code == 400:
            printe("Error %s: Bad request." % (reply.status_code), "MetaScan")
        elif reply.status_code == 403:
            printe("Error %s: Lookup rate limit reached, try again later." % (reply.status_code), "MetaScan")
        elif reply.status_code == 401:
            printe("Error %s: Invalid API key." % (reply.status_code), "MetaScan")
        elif reply.status_code == 503:
            printe("Error %s: Internal server error, service temporarily unavailable." % (reply.status_code), "MetaScan")
        else:
            printe("Error %s: Headers: %s Content: %s" % (reply.status_code, reply.headers, reply.content), "MetaScan")
    else:
        if str(reply.content) == "[]":
            printp("Address not found in dataset.")
        else:
            replies = json.loads(reply.content)
            for reply_dict in replies:
                printp("%s%s%s: \t%s detections, scanned at %s" % (c.BOLD, reply_dict['address'], c.END, reply_dict['detected_by'], reply_dict['start_time']))
                printl("Geolocation: %s: %s (lat. %s, lon. %s)" % (reply_dict['geo_info']['country_code'],
                                                                        reply_dict['geo_info']['country_name'],
                                                                        reply_dict['geo_info']['latitude'],
                                                                        reply_dict['geo_info']['longitude']))
                for i in reply_dict['scan_results']:
                    source = i['source']
                    for s in i['results']:
                        if s['result'] != "unknown":
                            printp("%s:" % source)
                            printl("Detection time: %s\tUpdate time:%s\tConfidence: %s" % (s['detecttime'], s['updatetime'], s['confident']))
                            printl("Result: %s%s%s \tAssessment: %s%s%s" % (c.Y, s['result'], c.END, c.Y, s['assessment'], c.END))
                            printl("Alternative ID: %s" % s['alternativeid'])
        run.append("MetaScan")
    if arg.pause:
        pause()
else:
    notRun.append("MetaScan")

# GOOGLE SAFE BROWSING API LOOKUP
if arg.googlesafebrowsing and Domain != "":
    try:
        run.append("Google Safe Browsing")
        printh("Querying Google Safe Browsing API with domain name")
        parameters = {
            'client': 'check-lookup-tool',
            'key': settings['GoogleAPIKey'],
            'appver': '1.0',
            'pver': '3.1',
            'url': Domain
        }
        reply = requests.get(
            "https://sb-ssl.google.com/safebrowsing/api/lookup",
            params=parameters,
            headers=headers)
        if reply.status_code == 200:
            printl("Status %s: Address http://%s/ found: %s" % \
            (reply.status_code, Domain, reply.text), c.Y)
        elif reply.status_code == 204:
            printl("Status %s: The requested URL is legitimate." % (reply.status_code), c.G)
        elif reply.status_code == 400:
            printe(
                "Status %s: Bad Request." %
                reply.status_code,
                "Google Safe Browsing")
        elif reply.status_code == 401:
            printe(
                "Status %s: Not Authorized" %
                (reply.status_code),
                "Google Safe Browsing")
        elif reply.status_code == 503:
            printe(
                "Status %s: Service Unavailable" %
                (reply.status_code),
                "Google Safe Browsing")
        else:
            printe(
                "Status %s: Unhandled reply: " %
                (reply.status_code),
                "Google Safe Browsing")
        pipe()
    except KeyError:
        printe("Google API key not present.", "Google Safe Browsing")
    if arg.pause:
        pause()
else:
    notRun.append("Google Safe Browsing")

# WEB OF TRUST API LOOKUP
if arg.weboftrust and Domain != "":
    try:
        run.append("Web Of Trust")
        printh("Querying Web Of Trust reputation API with domain name")
        target = 'http://' + Domain + '/'
        parameters = {'hosts': Domain + "/", 'key': settings['WebOfTrustAPIKey']}
        reply = requests.get(
            "http://api.mywot.com/0.4/public_link_json2",
            params=parameters,
            headers=headers)
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
            for key, value in reply_dict[Domain].iteritems():
                if key == "target":
                    printp(
                        "Server response OK, Web Of Trust Reputation Score for %s%s%s:" %
                        (c.BOLD, value, c.END))
                elif key == "1":
                    ()  # Deprecated
                elif key == "2":
                    ()  # Deprecated
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
                        pipe()
                        printl("Trustworthiness:\t %s (%s) \t[%s%% confidence]" % (value[0], assessment, value[1]))
                    elif key == "4":
                        printl("Child safety:\t %s (%s) \t[%s%% confidence]" % (value[0], assessment, value[1]))
                elif key == "categories":
                    pipe()
                    hasKeys = True
                    for e, s in value.iteritems():
                        printl("Category:\t %s \t[%s%% confidence]" % (categories[e], s))
                    pipe()
                elif key == "blacklists":
                    hasKeys = True
                    for e, s in value.iteritems():
                        printl("Blacklisted:\t %s \tID: %s" % (e, s))
                else:
                    printe("Unknown key %s => %s" % (key, value), "Web Of Trust")
        if hasKeys == False:
            printl("Web Of Trust has no records for %s" % (Domain), c.G)
            pipe()
        if reply.status_code != 200:
            printe(
                "Server returned status code %s see https://www.mywot.com/wiki/API for details." %
                reply.status_code, "Web Of Trust")
    except KeyError:
        printe("Web Of Trust API key not present.", "Web Of Trust")
    if arg.pause:
        pause()
else:
    notRun.append("Web Of Trust")

# VIRUSTOTAL
if arg.virustotal:
    try:
        run.append("VirusTotal")
        printh("Querying VirusTotal for %s..." % IPaddr)
        if IPaddr != "":
            parameters_ip = {
                'ip': IPaddr,
                'apikey': settings['VirusTotalAPIKey']
            }
            vtresponse_ip = requests.get(
                'https://www.virustotal.com/vtapi/v2/ip-address/report',
                params=parameters_ip).content
            vtresponse_dict = json.loads(vtresponse_ip)
            if vtresponse_dict['response_code'] == 0:
                printp("VirusTotal response: IP address not in dataset.")
            else:
                printp("VirusTotal response code %s: %s" % (vtresponse_dict['response_code'], vtresponse_dict['verbose_msg']))
                for entry in vtresponse_dict['resolutions']:
                    printl("%s Last resolved: %s" % (entry['hostname'], entry['last_resolved']))
                pipe()
                if len(vtresponse_dict['detected_urls']) >= 1:
                    printl("Detections in this IP address:", c.Y)
                    for entry in vtresponse_dict['detected_urls']:
                        if len(entry['url']) <= 80:
                            printl(entry['url'].replace("http", "hxxp"))
                        else:
                            printl(entry['url'][0:90] + c.Y +  "...".replace("http", "hxxp"))
                        if entry['positives'] >= 1:
                            printl("Positives: %s%s%s\tTotal:%s\tScan date:%s" % (c.R, entry['positives'], c.END, entry['total'], entry['scan_date']))
                        else:
                            printl("Positives: %s\tTotal:%s\tScan date:%s" % (entry['positives'], entry['total'], entry['scan_date']))

        if Domain != "":
            parameters_domain = {
                'domain': Domain,
                'apikey': settings['VirusTotalAPIKey']
            }
            vtresponse_domain = requests.get(
                'https://www.virustotal.com/vtapi/v2/domain/report',
                params=parameters_domain).content
            vtresponse_dict = json.loads(vtresponse_domain)
            if vtresponse_dict['response_code'] == 0:
                printp("VirusTotal response: IP address not in dataset.")
            else:
                printp("VirusTotal response code %s: %s" % (vtresponse_dict['response_code'], vtresponse_dict['verbose_msg']))
                for entry in vtresponse_dict['resolutions']:
                    printl("%s Last resolved: %s" % (entry['ip_address'], entry['last_resolved']))
                pipe()
                if len(vtresponse_dict['detected_urls']) >= 1:
                    printl("Detections in this IP address:", c.Y)
                    for entry in vtresponse_dict['detected_urls']:
                        if len(entry['url']) <= 80:
                            printl(entry['url'].replace("http", "hxxp"))
                        else:
                            printl(entry['url'][0:90] + c.Y +  "...".replace("http", "hxxp"))
                        if entry['positives'] >= 1:
                            printl("Positives: %s%s%s\tTotal:%s\tScan date:%s" % (c.R, entry['positives'], c.END, entry['total'], entry['scan_date']))
                        else:
                            printl("Positives: %s\tTotal:%s\tScan date:%s" % (entry['positives'], entry['total'], entry['scan_date']))

    except KeyError:
        ()
    if arg.pause:
        pause()
else:
    notRun.append("VirusTotal")

# BLACKLISTS
if arg.blacklists:
    sourceCount = 0
    matchcollector = []
    run.append("Blacklists")
    removed = trimcache(48)  # Delete entries older than (h)
    printh("Cache trim: %s files (%s MB) removed, current cache size %s MB." % removed)
    totalLines = 0
    if os.path.isfile(blacklistSourceFile):
        with open(blacklistSourceFile) as sourcefile:
            blacklists = sourcefile.readlines()
            sourceCount = 0
    else:
        printe(
            "No blacklist file found at %s" %
            blacklistSourceFile,
            "blacklist")
        blacklists = ""
        cachefilew = open(os.devnull, "w+")
        cachefiler = open(os.devnull, "r+")
    for line in blacklists:
        if line[:1] == "#":
            continue
        else:
            sourceCount += 1

    printh("Searching local blacklists...")
    localfiles = os.listdir(ownPath + "localdata")
    for file in localfiles:
        if file[0] == ".":
            continue
        domainmatch = ipmatch = rangematch = False
        printp("Processing local blacklist file %s%s%s" % (c.BOLD, file, c.END))
        file = ownPath + "localdata/" + file
        file = open(file, "r+")
        output = matchfinder(file.read().splitlines())
        for line in output:
            printl(line)

    printh("Downloading and searching from remote blacklists...")
    i = 0
    cacherefreshcount = 0
    for sourceline in blacklists:
        sourceline = sourceline.split("|")
        sourceurl = sourceline[0].replace("\n", "").replace(" ^", "")
        if sourceurl[:1] == "#":
            continue  # Skip comment lines
        try:
            sourcename = sourceline[1].replace("\n", "")
        except IndexError:
            # If no name specified use URL.
            sourcename = sourceline[0].replace("\n", "")
        i += 1
        listfile = ""
        linecount = 0
        domainmatch = False
        ipmatch = False
        printp(
            "Downloading from %s%s%s [%s of %s sources]:" %
            (c.BOLD, sourcename, c.END, i, sourceCount))
        try:
            data = ""
            head = requests.head(sourceurl, headers=headers)
        except Exception:
            printe("[%sFail!%s] Unable to connect to %s" % (c.R, c.END, sourcename), "blacklists")
            continue
        try:
            timestamp = head.headers['Last-Modified']
        except KeyError:
            timestamp = "1970-01-02 00:00:00"
        eStamp = int(time.mktime(dateutil.parser.parse(timestamp).timetuple()))
        agediff = eNow - eStamp
        filehash = hashlib.md5(sourceurl.encode('utf-8')).hexdigest()
        cachepath = ownPath + "cache/" + str(eStamp) + "-" + filehash
        if eStamp == 79200:
            usecache = False
        else:
            usecache = os.path.isfile(cachepath)
        if usecache:
            if agediff >= 60:
                age = "%s%s%s minutes ago" % (c.G, (agediff / 60), c.END)
            if agediff >= 3600:
                age = "%s%s%s hours ago" % (c.G, (agediff / 3600), c.END)
            if agediff >= 86400:
                if (agediff / 86400) >= 14:
                    age = "%s%s%s days ago, %sstale source?%s" % (
                        c.R, (agediff / 86400), c.END, c.R, c.END)
                else:
                    age = "%s%s%s days ago" % (c.Y, (agediff / 86400), c.END)
            printl("[%sCache%s] Using a cached copy. Source updated %s." % (c.B, c.END, age))
            cachefiler = gzip.open(cachepath, "r+")
            cachefilew = open(os.devnull, "w+")
        else:
            # os.remove(cachefilew)
            cachefilew = gzip.open(cachepath, "w+")
            cachefiler = open(os.devnull, "r+")
        if usecache:
            lines = cachefiler.readlines()
            for line in lines:
                linecount += 1
            printl("Searching from %s lines." % (linecount))
            totalLines = totalLines + (linecount - 1)
            req = None
            output = matchfinder(lines)
            for line in output:
                printl(line)
        if not usecache:
            cacherefreshcount += 1
            req = requests.get(sourceurl, stream=True, headers=headers)
            try:
                cd = req.headers['Content-Disposition']
            except Exception:
                cd = ""
            filesize = req.headers.get('content-length')
            if not filesize:
                # Assuming no content-length header or content-type
                sys.stdout.write(
                    g.PIPE +
                    "[" +
                    c.G +
                    "Done!" +
                    c.END +
                    "] Content-length not received. " +
                    cd +
                    c.END)
                data = req.content
                cType = "text/plain"
            else:
                cType = req.headers.get('content-type')
                if not cType:
                    cType = "text/plain"
                sys.stdout.write(g.PIPE +
                                 "[" +
                                 c.R +
                                 "     " +
                                 c.END +
                                 "] Filesize: " +
                                 str(int(filesize) /
                                     1024) +
                                 " kb \tContent type: " +
                                 str(cType) +
                                 " \r" +
                                 g.PIPE +
                                 "[")
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
                while count < 5:  # Fill the meter if the chunks round down.
                    count += 1
                    sys.stdout.write(c.G + "!" + c.END)
                    sys.stdout.flush()
            if "application/zip" in cType:
                filelist = {}
                zip_file_object = zipfile.ZipFile(StringIO.StringIO(data))
                for info in zip_file_object.infolist(
                ):  # Get zip contents and put to a list
                    # Add files to a list
                    filelist[info.filename] = info.file_size
                # Sort list by value; largest file is last
                sortedlist = sorted(
                    filelist.items(), key=operator.itemgetter(1))
                for key, value in sortedlist:  # Iterate over list - last assigned value is the largest file
                    largestfile = key
                    largestsize = value
                sys.stdout.write(
                    "\r\n" +
                    g.PIPE +
                    "Decompressing and using largest file in archive: %s (%s bytes)." %
                    (largestfile,
                     largestsize))
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
            output = matchfinder(listfile.splitlines())
            for line in output:
                printl(line)
    cachefiler.close()
    cachefilew.close()
    printp("A total of %s lines searched, %s cached files updated." % (totalLines, cacherefreshcount))
    if len(matchcollector) > 0:
        i = 0
        printp("Found %s matches:" % len(matchcollector))
        for line in matchcollector:
            i += 1
            printl("%s: %s" % (i, line))
    pipe()
else:
    notRun.append("Blacklists")

# SPAMLISTS
if arg.spamlists and IPaddr != "":
    run.append("Spamlists")
    printh("Querying spamlists for %s..." % IPaddr)
    for bl in sourceListSpamDNS:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(IPaddr).split("."))) + "." + bl
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            print g.PIPE + c.Y + 'IP: %s IS listed in %s (%s: %s)' % (IPaddr, bl, answers[0], answer_txt[0]) + c.END
        except dns.resolver.NoAnswer:
            ()
        except dns.resolver.NXDOMAIN:
            printl('IP: %s is NOT listed in %s' % (IPaddr, bl))
    pipe()
    if arg.pause:
        pause()
else:
    notRun.append("Spamlists")

# WHOIS
if arg.whois:
    run.append("Whois")
    results = results2 = ""
    try:
        results = subprocess.check_output("whois " + IPaddr, shell=True)
    except subprocess.CalledProcessError:
        printe("Whois returned an error.", "Whois")
    if Domain != "":
        try:
            results2 = subprocess.check_output("whois " + Domain, shell=True)
        except subprocess.CalledProcessError:
            printe("Whois returned an error.", "Whois")
    if results:
        printh("Querying IP Address %s" % IPaddr)
        for line in results.splitlines():
            if ("abuse" in line and "@" in line) or "address" in line or "person" in line or "phone" in line:
                printl(line, c.B)
            elif "descr" in line:
                printl(line, c.Y)
            else:
                printl(line)
        if arg.pause:
            pause()
    if results2:
        printh("Resolved address %s for domain %s" % (IPaddr, Domain))
        for line in results2.splitlines():
            if len(line) >= 80:
                line = line[0:80] + c.Y + "..." + c.END
            if "#" in line:
                ()
            elif ("abuse" in line and "@" in line) or "address" in line or "person" in line or "phone" in line:
                printl(line, c.B)
            elif "descr" in line:
                printl(line, c.Y)
            else:
                printl(line)
        if arg.pause:
            pause()
        pipe()
else:
    notRun.append("Whois")

### SCANPORTS & SCANHEADERS
if arg.scanports or arg.scanheaders:
    run.append("Portscan")
    printh("Scanning common ports...")
    socket.setdefaulttimeout(3)
    openports = []
    try:
        for port in targetPortscan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((IPaddr, port))
            if result == 0:
                printl("port %s is open." % port, c.G)
                openports.append(port)
            else:
                printl("port %s is closed." % port)
            sock.close()
        if arg.scanheaders and Domain != "":
            for port in openports:
                url = "http://" + Domain
                try:
                    if port == 443:
                        protocol = "https://"
                    else:
                        protocol = "http://"
                    pipe()
                    printp("Getting headers for %s%s:%s" % (protocol, Domain, port))
                    page = requests.head(
                        '%s%s:%s' %
                        (protocol, Domain, port), headers={
                            'user-agent': random.choice(uapool), 'referer': 'https://www.google.com'})
                    print g.PIPE + c.BOLD + "Server response code: %s" % page.status_code + c.END
                    for key, value in page.headers.items():
                        printl("%s: %s" % (key, value))
                except Exception as e:
                    printe(str(e), "Headerscan")
    except KeyboardInterrupt:
        printe("Caught Ctrl+C, interrupting...")
    except socket.gaierror:
        printe("Could not connect to address.")
    except socket.error:
        printe("Couldn't connect to server.")
    pipe()
    if arg.pause:
        pause()
else:
    notRun.append("Portscan")

# OPENSSL
if arg.cert and (IPaddr != "" or Domain !=""):
    run.append("OpenSSL")
    results = None
    try:
        results = subprocess.check_output(
            "echo | openssl s_client -showcerts -servername %s -connect %s:443 2>/dev/null | openssl x509 -inform pem -noout -text 2>/dev/null" %
            (Domain, Domain), shell=True)
        if results:
            printh("Certificate information for https://%s/" % Domain)
            for line in results.splitlines():
                if "Issuer" in line or "Subject:" in line or "DNS:" in line or "Not Before" in line or "Not After" in line:
                    printl(line.replace("  ", " "), c.B)
                else:
                    printl(line.replace("  ", " "))
    except subprocess.CalledProcessError:
        printe("OpenSSL returned an error.", "OpenSSL")
    if arg.pause:
        pause()
else:
    notRun.append("OpenSSL")

if logfile is not None:
    printh("Writing log file to %s" % logfile)
terminate()
