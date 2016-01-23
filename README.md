# check

This is a simple script to pull information about an IP address or domain.

It is also the first thing I've written in Python so that's what it looks like.

Depends on:
GeoIP (pip install geoip)
IPy (pip install IPy)
requests (pip install requests)
dnspython (https://github.com/rthalley/dnspython)
passivetotal (https://github.com/passivetotal/passivetotal_tools/),
install the python module from api_helpers
required system commands: "whois" and "ping"

Export your API keys as environmental variables;
VTAPIKEY for VirusTotal API key, PTAPIKEY for PassiveTotal. If not present,
those scans will be skipped.
add "export VTAPIKEY=yourapikey" to your shell startup script yo export.

if you get trouble email me at antti@kurittu.org and I'll try to help!
Tested with debian and OS X, I have no idea whether this thing works on
Windows.
