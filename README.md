# check

<p>This is a simple script to pull information about an IP address or domain.</p>

<p>It is also the <i>first thing I've written in Python</i> so that's what it looks like.</p>

Depends on:<br>
GeoIP (pip install geoip)<br>
IPy (pip install IPy)<br>
requests (pip install requests)<br>
dnspython (https://github.com/rthalley/dnspython)<br>
passivetotal (https://github.com/passivetotal/passivetotal_tools/), install the python module from api_helpers<br>
Required POSIX system commands: "whois" and "ping"

Export your API keys as environmental variables;<br>
VTAPIKEY for VirusTotal API key, PTAPIKEY for PassiveTotal. If not present,<br>
those scans will be skipped.<br>

if you get trouble email me at antti@kurittu.org and I'll try to help!<br>
Tested with debian and OS X, I have no idea or interest whether this thing works on Windows.<br>
