# check.py

<p>Check.py is an extended lookup tool to pull information about an IP address or domain.</p>

It currently does the following things (all or selectable):

- Query Google Safe Browsing API for website reputation.<br>
- Query Web Of Trust API for website reputation and categories.<br>
- Query and cache several domain- and IP blacklist sources for matches.<br>
- Query PassiveDNS from PassiveTotal and VirusTotal.<br>
- Query VirusTotal for matches for target address.<br>
- Query MetaScan for matches for target address<br>
- Search Twitter for mentions of domain name or IP address<br>
- Retrieve certificate information with OpenSSL<br>
- Query WHOIS for domain name and IP address.<br>
- Query local GeoIP database.<br>
- Query spam blocklists for address.<br>
- Ping the host.<br>
- Check common ports for available services.<br>
- Try to retrieve and show HTTP headers from said ports.<br>

<p>Some modules require registration to the service and a free API key.</p>

# Who needs this?

<p>I wrote this to quickly pull information on an network address of interest.
Usually to gather this information you need to run several commands and access
several websites - this script gathers everything in one place and formats the
output in a pleasing manner. With basic usage of "check.py -d example.com -a"
you can run all modules and save the output in a log file. For processing the
log file later on you can suppress colour and graphics.</p>

This might be useful for sysadmins, secops, investigators or whoever needs
to quickly and efficiently assess a network resource.

With default options it <i>does</i> contact the host directly, but there modules
that query external resources which can pull a lot of interesting information.

<p>It is also the <i>first thing I've written in Python</i> so that's what it looks like.</p>

API keys should be addedd to apikeys.conf, for which a template is automatically created on first run if the file is not found.

if you get trouble email me at antti@kurittu.org and I'll try to help!<br>
Tested with debian and OS X, I have no idea or interest whether this thing works on Windows.<br>
See requirements.txt for dependencies.

Better documentation coming up later...
