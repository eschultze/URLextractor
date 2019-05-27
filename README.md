# URLextractor

Information gathering & website reconnaissance
------

**Usage:**
`./extractor http://www.hackthissite.org/`

![](https://github.com/eschultze/URLextractor/blob/master/examples/example1.png)

**Tips:**
* Colorex: put colors to the ouput `pip install colorex` and use it like `./extractor http://www.hackthissite.org/ | colorex -g "INFO" -r "ALERT"`
* Tldextract: is used by dnsenumeration function `pip install tldextract`

Features:
------

* IP and hosting info like city and country (using [FreegeoIP](http://freegeoip.net/))
* DNS servers (using [dig](http://packages.ubuntu.com/precise/dnsutils))
* ASN, Network range, ISP name (using [RISwhois](https://www.ripe.net/analyse/archived-projects/ris-tools-web-interfaces/riswhois))
* Load balancer test
* Whois for abuse mail (using [Spamcop](https://www.spamcop.net/))
* PAC (Proxy Auto Configuration) file
* Compares hashes to diff code
* robots.txt (recursively looking for hidden stuff)
* Source code (looking for passwords and users)
* External links (frames from other websites)
* Directory FUZZ (like Dirbuster and Wfuzz - using [Dirbuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)) directory list)
* [URLvoid](http://www.urlvoid.com/) API - checks Google page rank, Alexa rank and possible blacklists 
* Provides useful links at other websites to correlate with IP/ASN
* Option to open ALL results in browser at the end

Changelog to version 0.2.0:
------

* [Fix] Changed GeoIP from freegeoip to ip-api
* [Fix/Improvement] Remove duplicates from robots.txt
* [Improvement] Better whois abuse contacts (abuse.net)
* [Improvement] Top passwords collection added to sourcecode checking
* [New feature] Firt run verification to install dependencies if need
* [New feature] Log file
* [New feature] Check for hostname on log file
* [New feature] Check if hostname is listed on Spamaus Domain Blacklist
* [New feature] Run a quick dnsenumeration with common server names

Changelog to version 0.1.9:
------

* Abuse mail using lynx istead of ~~curl~~
* Target server name parsing fixed
* More verbose about HTTP codes and directory discovery
* MD5 collection for IP fixed
* Links found now show unique URLs from array
* [New feature] **Google** results
* [New feature] **Bing** IP check for other hosts/vhosts
* [New feature] Opened ports from **Shodan**
* [New feature] **VirusTotal** information about IP
* [New feature] **Alexa Rank** information about $TARGET_HOST

Requirements:
------

Tested on Kali light mini AND OSX 10.11.3 with brew
```
sudo apt-get install bc curl dnsutils libxml2-utils whois md5sha1sum lynx openssl -y
```

**Configuration file:**
```
CURL_TIMEOUT=15 #timeout in --connect-timeout
CURL_UA=Mozilla #user-agent (keep it simple)
INTERNAL=NO #YES OR NO (show internal network info)
URLVOID_KEY=your_API_key #using API from http://www.urlvoid.com/
FUZZ_LIMIT=10 #how many lines it will read from fuzz file
OPEN_TARGET_URLS=NO #open found URLs at the end of script
OPEN_EXTERNAL_LINKS=NO #open external links (frames) at the end of script
FIRST_TIME=YES #if first time check for dependecies
```

Todo list:
------

* [x] Upload to github :)
* [x] Check for installed packages
* [ ] Integration with other APIs
* [ ] Export to CSV
* [ ] Integration with CipherScan

## Stargazers over time

[![Stargazers over time](https://starchart.cc/eschultze/URLextractor.svg)](https://starchart.cc/eschultze/URLextractor)
