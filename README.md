# check.py

<p>This is a simple script to pull information about an IP address or domain.</p>

It currently does the following things:

- Query a list of malware addresses for matches<br>
- Query WHOIS for domain name and IP address<br>
- Query PassiveDNS from PassiveTotal and VirusTotal<br>
- Query VirusTotal for matches coming from target address<br>
- Query spam blocklists for address
- Query local GeoIP database<br>
- Ping the host<br>
- Check common ports for available services<br>
- Try to retrieve and show HTTP headers from said ports<br>

<p>It is also the <i>first thing I've written in Python</i> so that's what it looks like.</p>

Export your API keys as environmental variables;<br>
VTAPIKEY for VirusTotal API key, PTAPIKEY for PassiveTotal. If not present,<br>
those scans will be skipped.<br>

if you get trouble email me at antti@kurittu.org and I'll try to help!<br>
Tested with debian and OS X, I have no idea or interest whether this thing works on Windows.<br>
