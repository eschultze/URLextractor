# URLextractor

Information gathering & website reconnaissance

**Usage:**
`./extractor http://www.hackthissite.org/`

![](https://github.com/eschultze/URLextractor/blob/master/examples/example1.png)

**Features:**
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

**Requirements:**
Tested on Kali light mini
```
sudo apt-get install bc curl dnsutils libxml2-utils whois -y
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
```

**Todo list:**
* [x] Upload to github :)
* [ ] Integration with other APIs
* [ ] Add  host regex validation
* [ ] Use GNU parallel to fuzz URLs
* [ ] Export to CSV
* [ ] Possible migration to python
