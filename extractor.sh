#!/bin/bash

erase_temp_files(){
        echo -e "\n[ALERT] OK... Let's close"
        rm -f URLs_$TARGET_HOST.txt $TARGET_DOMAIN.xml URLsExternal$TARGET_HOST.txt
        exit 130
}

trap erase_temp_files SIGINT

clear

source config.sh

if [[ $FIRST_TIME = "YES" ]]; then
	for APP in $(cat requirements); do sudo apt-get install $APP; done
	sed -i '10s/YES/NO/' config.sh
	clear
fi

TARGET=$1

echo -e "\e[1;32m##################################################"
echo -e "#                  URLextractor                  #"
echo -e "# Information Gathering & Website Reconnaissance #"
echo -e "#              coded by eschultze                #"
echo -e "#           https://phishstats.info/             #"
echo -e "#                version - 0.2.0                 #"
echo -e "##################################################\e[m"

date '+[INFO] Date: %d/%m/%y | Time: %H:%M:%S'
date_begin=$(date +"%s")

if [[ $INTERNAL != "NO" ]]; then
        echo [INFO] ----Machine info----
        distrib=$(cat /etc/issue | cut -d' ' -f1)
        echo [*] Distribution: $distrib
        user=$(whoami)
        echo [*] User: $user
        echo [INFO] ----Network info----
        rede=$(ifconfig | awk '{print$1}' | grep 'eth\|lo\|lan\|pan\|vmnet' | grep ':' | cut -d':' -f1 | head -1)
        echo [*] Network interface: $rede
        internal=$(ifconfig | grep "inet " | awk '{print$2}' | head -1)
        echo [*] Internal IP: $internal

        EXTERNAL_IP=$(curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT http://ipinfo.io/ip)
        GEOIP=$(curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT http://ip-api.com/csv/$EXTERNAL_IP) echo [*] External IP: $EXTERNAL_IP
        EXTERNAL_IP_CC=$(echo $GEOIP | cut -d',' -f2 | cut -d '"' -f2) && echo [*] CC: $EXTERNAL_IP_CC

        TRIES=0
        TRIES_MAX=6
        while [[ $EXTERNAL_IP_CC = "Try again later" ]] || [[ $EXTERNAL_IP_CC = "" ]]; do
                echo "[ALERT] Problem with IP-API detected... trying to reconnect with $CURL_TIMEOUT seconds timeout. Number of tries: $TRIES/$TRIES_MAX"
                TRIES=$((TRIES+1))
                GEOIP=`curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT http://ip-api.com/csv/$EXTERNAL_IP`
                EXTERNAL_IP_CC=`echo $GEOIP | cut -d',' -f2 | cut -d '"' -f2`
                echo [*] Number of tries: $TRIES

                if [[ $TRIES -ge 6 ]]; then
                        echo "[ALERT] It seems IP-API is currently DOWN... exiting"
                        exit 1
                fi
        done

        EXTERNAL_IP_CN=$(echo $GEOIP | cut -d',' -f3 | cut -d '"' -f2) && echo [*] Country: $EXTERNAL_IP_CN
        EXTERNAL_IP_RG=$(echo $GEOIP | cut -d',' -f4 | cut -d '"' -f2) && echo [*] RegionCode: $EXTERNAL_IP_RG
        EXTERNAL_IP_RN=$(echo $GEOIP | cut -d',' -f5 | cut -d '"' -f2) && echo [*] RegionName: $EXTERNAL_IP_RN
        EXTERNAL_IP_CITY=$(echo $GEOIP | cut -d',' -f6 | cut -d '"' -f2) && echo [*] City: $EXTERNAL_IP_CITY
	EXTERNAL_MAP=$(echo $GEPIP | cut -d',' -f8-9) && echo [*] GoogleMaps: https://www.google.com/maps/@$EXTERNAL_MAP,10z

        WHOIS_IP=`whois -h riswhois.ripe.net $EXTERNAL_IP | egrep "route|origin|descr" | head -4`
        EXTERNAL_IP_ASN=$(echo $WHOIS_IP | awk '{print$13}') && echo [*] ASN: $EXTERNAL_IP_ASN
        EXTERNAL_IP_BGP=$(echo $WHOIS_IP | awk '{print$11}') && echo [*] BGP_PREFIX: $EXTERNAL_IP_BGP
        EXTERNAL_IP_ISP=$(echo $WHOIS_IP | cut -d' ' -f15-28) && echo [*] ISP: $EXTERNAL_IP_ISP

fi

        TARGET_HOST=$(echo $TARGET | cut -d'/' -f3 | cut -d':' -f1)
if [[ -z $TARGET ]]; then
        echo "[ALERT] NO target set"
        echo "[ALERT] USAGE: ./extractor http://site.com/ OR http://site.com/path/dir/file.php OR http://site.com/path/proxy.pac"
        exit 1
else
        TARGET=$(curl --fail -A $CURL_UA -L --write-out "%{url_effective}\n" --silent --connect-timeout $CURL_TIMEOUT --output /dev/null $1)

        echo [INFO] ------TARGET info------
        echo [*] TARGET: $TARGET

        GEOIP=$(curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT http://ip-api.com/csv/$TARGET_HOST)
        TARGET_IP=$(echo $GEOIP | cut -d',' -f1 | cut -d '"' -f2)

	LOG_IP=`cat log.csv | cut -d',' -f2 | grep $TARGET_IP | wc -l | sed -e 's/^[ \t]*//'`
        if [[ $LOG_IP -ge 1 ]]; then
                echo "[*] Same IP $TARGET_IP was previously analyzed $LOG_IP time(s)"
        fi

        LOG_TARGET=`cat log.csv | cut -d',' -f3 | grep $TARGET | wc -l | sed -e 's/^[ \t]*//'`
        if [[ $LOG_TARGET -ge 1 ]]; then
                echo "[*] Same target $TARGET was previously analyzed $LOG_TARGET time(s)"
        fi

        TRIES=0
        TRIES_MAX=6
        while [[ $TARGET_IP = "Try again later" ]] || [[ $TARGET_IP = "" ]]; do
                TRIES=$((TRIES+1))
                echo "[ALERT] Problem with IP-API detected... trying to reconnect with $CURL_TIMEOUT seconds timeout. Number of tries: $TRIES/$TRIES_MAX"
                GEOIP=`curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT http://ip-api.com/csv/$TARGET_HOST`
                TARGET_IP=`echo $GEOIP | cut -d',' -f1 | cut -d '"' -f2`

                if [[ $TRIES -ge 6 ]]; then
                        echo "[ALERT] It seems IP-API is currently DOWN... exiting"
                        exit 1
                fi
        done

        if [[ $TARGET_IP =~ "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$" ]]; then
                echo [*] TARGET IP: $TARGET_IP
        else
                TARGET_IP=$(host $TARGET_HOST | grep "has address" | cut -d' ' -f4 | head -1)
                if [[ -z  $TARGET_IP ]]; then
                        echo "[ALERT] It seems $TARGET is OFFLINE... exiting"
                        exit 1
                else
                        echo [*] TARGET IP: $TARGET_IP
                fi
        fi

        TARGET_LOADB=$(host $TARGET_HOST | grep "has address" | wc -l | sed -e 's/^[ \t]*//')
        if [[ $TARGET_LOADB -ge 2 ]]; then
                echo "[ALERT] $TARGET_HOST has a load balancer for IPv4 with the following IPs:"
                for TARGET_LOADB_IP in $(host $TARGET_HOST | grep "has address" | cut -d' ' -f4)
                do
                        echo [*] $TARGET_LOADB_IP
                done
        else
                echo "[INFO] NO load balancer detected for $TARGET_HOST..."
        fi

        TARGET_DNS=$(dig -t SOA $TARGET_HOST | grep -A1 "AUTHORITY SECTION\|ANSWER SECTION" | awk '{print$5}' | sed '/^$/d') && echo [*] DNS servers: ${TARGET_DNS[@]}

        TARGET_SERVER=$(curl -A $CURL_UA -I -L --silent http://$TARGET_HOST/ | grep Server: | uniq | cut -d' ' -f2-10) && echo [*] TARGET server: $TARGET_SERVER
        TARGET_IP_CC=$(echo $GEOIP | cut -d',' -f3 | cut -d '"' -f2) && echo [*] CC: $TARGET_IP_CC
        TARGET_IP_CN=$(echo $GEOIP | cut -d',' -f2 | cut -d '"' -f2) && echo [*] Country: $TARGET_IP_CN
        TARGET_IP_RG=$(echo $GEOIP | cut -d',' -f4 | cut -d '"' -f2) && echo [*] RegionCode: $TARGET_IP_RG
        TARGET_IP_RN=$(echo $GEOIP | cut -d',' -f5 | cut -d '"' -f2) && echo [*] RegionName: $TARGET_IP_RN
        TARGET_IP_CITY=$(echo $GEOIP | cut -d',' -f6 | cut -d '"' -f2) && echo [*] City: $TARGET_IP_CITY

        WHOIS_IP=`whois -h riswhois.ripe.net $TARGET_IP | egrep "route|origin|descr" | head -4`
        TARGET_IP_ASN=$(echo $WHOIS_IP | awk '{print$13}') && echo [*] ASN: $TARGET_IP_ASN
        TARGET_IP_BGP=$(echo $WHOIS_IP | awk '{print$11}') && echo [*] BGP_PREFIX: $TARGET_IP_BGP
        TARGET_IP_ISP=$(echo $WHOIS_IP | cut -d' ' -f15-28) && echo [*] ISP: $TARGET_IP_ISP

	if [[ $TARGET =~ ^https ]]; then
	echo "[INFO] SSL/HTTPS certificate detected"
	SSL_ISSUER=`echo | openssl s_client -servername $TARGET_HOST -connect $TARGET_HOST:443 2>/dev/null | openssl x509 -noout -issuer -subject | grep "issuer"` && echo [*] Issuer: $SSL_ISSUER
	SSL_SUBJECT=`echo | openssl s_client -servername $TARGET_HOST -connect $TARGET_HOST:443 2>/dev/null | openssl x509 -noout -issuer -subject | grep "subject"` && echo [*] Subject: $SSL_SUBJECT
	SSL_ISSUER_LETS=`echo $SSL_ISSUER | grep -oiE "let.?s.?encrypt"`
		if [[ $SSL_ISSUER_LETS != "" ]]; then
		echo "[ALERT] Let's Encrypt is commonly used for Phishing"
		fi
	fi

	TLD_EXTRACT=$(which tldextract)
	if [[ $TLD_EXTRACT != "" ]]; then
	TARGET_DOMAIN=$(tldextract $TARGET_HOST | rev | cut -d' ' -f1-2 | rev | sed 's/ /./g')

	echo "[INFO] DNS enumeration:"
	for DOMAIN_ENUM in $(cat domain_enum)
	do
		DOMAIN_ENUMTEST=$(dig +short $DOMAIN_ENUM.$TARGET_DOMAIN | xargs)
		if [[ $DOMAIN_ENUMTEST != "" ]]; then
		echo -e "[*] $DOMAIN_ENUM.$TARGET_DOMAIN \t $DOMAIN_ENUMTEST"
		fi
	done
	fi

	TEMP_MAIL_ARRAY=()
        echo "[INFO] Possible abuse mails are:"
        for TEMP_MAIL in $(curl -L -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT "https://www.spamcop.net/sc?track=$TARGET_IP" | grep -oE 'mailto:.*' | grep -v bait | cut -d':' -f2 | cut -d'"' -f1)
        do
                TEMP_MAIL_ARRAY+=($TEMP_MAIL)
        done
	for TEMP_MAIL in $(dig -t TXT +short $TARGET_HOST.contacts.abuse.net | sed 's/"//g')
	do
		TEMP_MAIL_ARRAY+=($TEMP_MAIL)
	done

	SPAMHAUS_DBL=$(dig +short $TARGET_HOST.dbl.spamhaus.org)
	if [[ $SPAMHAUS_DBL != "" ]]; then
		echo "[ALERT] $TARGET_HOST is listed on SpamHaus Domain Blacklist"
	fi


	for TEMP_MAIL in ${TEMP_MAIL_ARRAY[@]}; do echo [*] $TEMP_MAIL; done | sort -u

        PAC_TEST=$(curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT $TARGET | grep -o FindProxyForURL)
        if [[ "$PAC_TEST" = "FindProxyForURL" ]]; then
                PAC_PROXY=$(curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT $TARGET | grep PROXY | grep -oE "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):([0-9]{1,5})")
                echo "[ALERT] PAC (Proxy Auto Configuration) file found with possible PROXY: $PAC_PROXY"
        else
                echo "[INFO] NO PAC (Proxy Auto Configuration) file FOUND"
        fi

        TARGET_PATH=$(echo $TARGET | cut -d'/' -f4-20)
        FOLDER_COUNT=$(echo $TARGET_PATH | tr "/" " " | wc -w | sed -e 's/^[ \t]*//')
        if [[ $FOLDER_COUNT -ge 2 ]]; then
                echo "[INFO] Checking for HTTP status codes recursively from /$TARGET_PATH"
                echo -e "[INFO] Status code \t Folders "
                for (( dir = 1; dir < $FOLDER_COUNT; dir++ )); do
                        TEMP_PATH=`echo $TARGET_PATH | cut -d '/' -f1-$dir`
                        TEMP_HTTP_CODE=`curl -A $CURL_UA -L --write-out "%{http_code}\n" --silent --connect-timeout $CURL_TIMEOUT --output /dev/null "http://$TARGET_HOST/$TEMP_PATH"`
                        echo -e "[*] \t $TEMP_HTTP_CODE \t\t http://$TARGET_HOST/$TEMP_PATH/"
                        echo "http://$TARGET_HOST/$TEMP_PATH/" >> URLs_$TARGET_HOST.txt
                done
        fi

        ROBOTS=$(curl -A $CURL_UA -L --write-out "%{http_code}\n" --silent --connect-timeout $CURL_TIMEOUT --output /dev/null "http://$TARGET_HOST/robots.txt")
        if [[ $ROBOTS = 200 ]]; then
                echo "[ALERT] robots.txt file FOUND in http://$TARGET_HOST/robots.txt"
                echo "[INFO] Checking for HTTP status codes recursively from http://$TARGET_HOST/robots.txt"
                echo -e "[INFO] Status code \t Folders "
                for TEMP_ROBOTS in $(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT "http://$TARGET_HOST/robots.txt" | grep -oE "^(All.*|Dis.*).*" | cut -d' ' -f2 | sort | uniq)
                do
                        ROBOTS_CODE=`curl -L -A $CURL_UA --write-out "%{http_code}\n" --silent --connect-timeout $CURL_TIMEOUT --output /dev/null "http://$TARGET_HOST$TEMP_ROBOTS"`
                        if [[ $ROBOTS_CODE =~ ^2 ]] || [[ $ROBOTS_CODE =~ ^3 ]]; then
                                echo -e "[*] \t $ROBOTS_CODE \t\t http://$TARGET_HOST$TEMP_ROBOTS"
                                echo http://$TARGET_HOST$TEMP_ROBOTS >> URLs_$TARGET_HOST.txt
                        fi
                done
        fi

        echo "[INFO] Starting FUZZing in http://$TARGET_HOST/FUzZzZzZzZz..."
        echo -e "[INFO] Status code \t Folders "
        cat fuzz | head -$FUZZ_LIMIT | while read DIR
        do
                FUZZ_CODE=`curl -L -A $CURL_UA --write-out "%{http_code}\n" --silent --connect-timeout $CURL_TIMEOUT --output /dev/null "http://$TARGET_HOST/$DIR"`
                if [[ $FUZZ_CODE =~ ^2 ]] || [[ $FUZZ_CODE =~ ^3 ]]; then
                        echo -e "[*] \t $FUZZ_CODE \t\t http://$TARGET_HOST/$DIR"
                        echo http://$TARGET_HOST/$DIR >> URLs_$TARGET_HOST.txt
                fi
        done

        PASS1=$(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT $TARGET | grep -Ei "0|1234|12345|111111|121212|123123|123321|123456|555555|654321|654321|666666|696969|1234567|7777777|12345678|123456789|987654321|1234567890|123qwe|18atcskd2w|1q2w3e|1q2w3e4r|1q2w3e4r5t|1qaz2wsx|3rjs1la7qe|abc123|access|admin|adobe123|ashley|azerty|bailey|baseball|batman|dragon|flower|Football|freedom|google|hello|hottie|iloveyou|jesus|letmein|login|loveme|master|michael|monkey|mustang|mynoob|ninja|passw0rd|password|password1|photoshop|princess|qazwsx|qwerty|qwertyuiop|shadow|solo|starwars|sunshine|superman|trustno1|welcome|whatever|zaq1zaq1|zxcvbnm")
        PASS2=$(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT http://$TARGET_HOST/ | grep -Ei "0|1234|12345|111111|121212|123123|123321|123456|555555|654321|654321|666666|696969|1234567|7777777|12345678|123456789|987654321|1234567890|123qwe|18atcskd2w|1q2w3e|1q2w3e4r|1q2w3e4r5t|1qaz2wsx|3rjs1la7qe|abc123|access|admin|adobe123|ashley|azerty|bailey|baseball|batman|dragon|flower|Football|freedom|google|hello|hottie|iloveyou|jesus|letmein|login|loveme|master|michael|monkey|mustang|mynoob|ninja|passw0rd|password|password1|photoshop|princess|qazwsx|qwerty|qwertyuiop|shadow|solo|starwars|sunshine|superman|trustno1|welcome|whatever|zaq1zaq1|zxcvbnm")
        PASS3=$(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT http://$TARGET_IP/ | grep -Ei "0|1234|12345|111111|121212|123123|123321|123456|555555|654321|654321|666666|696969|1234567|7777777|12345678|123456789|987654321|1234567890|123qwe|18atcskd2w|1q2w3e|1q2w3e4r|1q2w3e4r5t|1qaz2wsx|3rjs1la7qe|abc123|access|admin|adobe123|ashley|azerty|bailey|baseball|batman|dragon|flower|Football|freedom|google|hello|hottie|iloveyou|jesus|letmein|login|loveme|master|michael|monkey|mustang|mynoob|ninja|passw0rd|password|password1|photoshop|princess|qazwsx|qwerty|qwertyuiop|shadow|solo|starwars|sunshine|superman|trustno1|welcome|whatever|zaq1zaq1|zxcvbnm")

        if [[ $PASS1 != "" ]] || [[ $PASS2 != "" ]] || [[ $PASS3 != "" ]]; then
                echo "[ALERT] Look in the source code. It may contain passwords"
        else
                echo "[INFO] NO passwords found in source code" 
        fi

        WWW_CHECK=$(echo $TARGET_HOST | grep -o www)
        MD1=$(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT http://$TARGET_HOST/ | md5sum | cut -d' ' -f1)

        if [[ -z $WWW_CHECK ]]; then
                MD2=$(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT "http://www.$TARGET_HOST/" | md5sum | cut -d' ' -f1)
                REDIR1=$(curl -A $CURL_UA -L --write-out "%{url_effective}\n" --silent --connect-timeout $CURL_TIMEOUT --output /dev/null http://$TARGET_HOST/)
                REDIR2=$(curl -A $CURL_UA -L --write-out "%{url_effective}\n" --silent --connect-timeout $CURL_TIMEOUT --output /dev/null "http://www.$TARGET_HOST/")

                if [[ $MD1 != $MD2 ]]; then
                        echo "[ALERT] Content in http://$TARGET_HOST/ AND http://www.$TARGET_HOST/ is different"
                        echo "[INFO] MD5 for http://$TARGET_HOST/ is: $MD1"
                        echo "[INFO] MD5 for http://www.$TARGET_HOST/ is: $MD2"
                        echo "[INFO] http://$TARGET_HOST/ redirects to $REDIR1"
                        echo "[INFO] http://www.$TARGET_HOST/ redirects to $REDIR2"

                        echo http://$TARGET_HOST/ >> URLs_$TARGET_HOST.txt
                        echo http://www.$TARGET_HOST/ >> URLs_$TARGET_HOST.txt

                        URL_ARRAY=($TARGET http://$TARGET_HOST/ http://$TARGET_IP/)
                fi
        fi

        MD3=$(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT "http://$TARGET_IP/" | md5sum | cut -d' ' -f1)
        if [[ $MD1 = $MD3 ]]; then
                echo "[INFO] SAME content in http://$TARGET_HOST/ AND http://$TARGET_IP/"
                URL_ARRAY=($TARGET)
        else
                URL_ARRAY=($TARGET http://$TARGET_IP/)
        fi

        for TEMP_ARRAY in $(echo ${URL_ARRAY[*]})
        do
                TEMP_LINK=`lynx -dump -force_html -listonly -nonumbers -accept_all_cookies -width=160 "$TEMP_ARRAY" | grep "^http\|^ftp\|^irc" | sort | uniq >> URLsExternal$TARGET_HOST.txt`
        done
        echo "[INFO] Links found from ${URL_ARRAY[*]}:"
        if [[ -s URLsExternal$TARGET_HOST.txt ]]; then
                cat URLsExternal$TARGET_HOST.txt | sort | uniq | while read LINKS
                do
                        echo [*] $LINKS
                done
        fi

	if [[ $TLD_EXTRACT = "" ]]; then
        HOST_COUNT=$(echo $TARGET_HOST | tr "." " " | wc -w | sed -e 's/^[ \t]*//')
        if [[ $HOST_COUNT -ge 3 ]]; then
                CUT_TEMP=$(echo $HOST_COUNT -1 | bc)
                TARGET_DOMAIN=$(echo $TARGET_HOST | cut -d'.' -f$CUT_TEMP-$HOST_COUNT)
        else
                TARGET_DOMAIN=$TARGET_HOST
        fi
	fi

        if [[ $URLVOID_KEY != "" ]]; then
                echo "[INFO] URLvoid API information:"
                curl -L -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT http://api.urlvoid.com/api1000/$URLVOID_KEY/host/$TARGET_DOMAIN/ > $TARGET_DOMAIN.xml
                IFS=$'\n' && for URL_VOID_F in $(cat xml_fields)
                do
                        URL_VOID_F1=$(echo $URL_VOID_F | cut -d',' -f1)
                        URL_VOID_F2=$(echo $URL_VOID_F | cut -d',' -f2)
                        URLVOID_RESULT=$(xmllint --xpath "string(//$URL_VOID_F1)" $TARGET_DOMAIN.xml)
                        if [ ! -z $URLVOID_RESULT ]
                        then
                                echo "[*] $URL_VOID_F2: $URLVOID_RESULT"
                        else
                                echo "[*] $URL_VOID_F2: EMPTY"
                        fi
                done
        fi

        if [[ $OPEN_TARGET_URLS != "NO" ]]; then
                COUNT=1
                cat URLs_$TARGET_HOST.txt | cut -d' ' -f2 | while read URL 
                do
                        if [[ $COUNT -le 1 ]]; then
                                COUNT=$((COUNT+1))
                                xdg-open $URL 2>/dev/null
                                sleep 5
                        else
                                xdg-open $URL 2>/dev/null
                                sleep 1
                        fi
                done
        fi


        if [[ $OPEN_EXTERNAL_LINKS != "NO" ]]; then
                COUNT=1
                cat URLsExternal$TARGET_HOST.txt | cut -d' ' -f2 | while read URL 
                do
                        if [[ $COUNT -le 1 ]]; then
                                COUNT=$((COUNT+1))
                                xdg-open $URL 2>/dev/null
                                sleep 5
                        else
                                xdg-open $URL 2>/dev/null
                                sleep 1
                        fi
                done
        fi

        LYNX_GOOGLE_COUNT=`lynx -dump -force_html -nolist -accept_all_cookies -width=160 "http://google.com/search?q=$TARGET_HOST" | grep "result" | wc -w | sed -e 's/^[ \t]*//'`
        LYNX_GOOGLE_COUNT_TEMP=`echo $LYNX_GOOGLE_COUNT -3 | bc`

        LYNX_GOOGLE=$(lynx -dump -force_html -nolist -accept_all_cookies -width=160 "http://google.com/search?q=$TARGET_HOST" | grep "result" | sed -e 's/^[ \t]*//' | cut -d' ' -f$LYNX_GOOGLE_COUNT_TEMP-$LYNX_GOOGLE_COUNT)
        if [[ $LYNX_GOOGLE != "" ]]; then
                echo [INFO] GOOGLE has $LYNX_GOOGLE about http://$TARGET_HOST/
        fi

        LYNX_BING_IP=$(lynx -dump -force_html -nolist -accept_all_cookies -width=160 "http://www.bing.com/search?q=ip%3A$TARGET_IP" | grep "resultsDate" | awk '{print$1}')
        if [[ $LYNX_BING_IP != "" ]]; then
                echo [INFO] BING shows $TARGET_IP is shared with $LYNX_BING_IP hosts/vhosts
        fi

        echo [INFO] Shodan detected the following opened ports on $TARGET_IP:
        for SHODAN_PROTO in $(lynx -dump -force_html -nolist -accept_all_cookies "https://www.shodan.io/host/$TARGET_IP" | grep '*' | grep -o '[0-9]*' | sort | uniq)
        do
                echo [*] $SHODAN_PROTO
        done

        echo "[INFO] ------VirusTotal SECTION------"
        echo "[INFO] VirusTotal passive DNS only stores address records. The following domains resolved to the given IP address:"
        IFS=$'\n' && for VIRUST_DNS in $(lynx -dump -force_html -nolist -accept_all_cookies -width=160 "https://www.virustotal.com/pt/ip-address/$TARGET_IP/information/" | grep -A10 'passive DNS only stores address records' | grep -v '/' | grep -o '20.*' | column -t)
        do
                echo [*] $VIRUST_DNS
        done


        echo "[INFO] Latest URLs hosted in this IP address detected by at least one URL scanner or malicious URL dataset:"
        IFS=$'\n' && for VIRUST_URLS_D in $(lynx -dump -force_html -nolist -accept_all_cookies -width=160 "https://www.virustotal.com/pt/ip-address/$TARGET_IP/information/" | grep -A10 'URLs hosted in this IP address' | grep "$TARGET_HOST" | column -t)
        do
                echo [*] $VIRUST_URLS_D
        done

        echo "[INFO] Latest files that are not detected by any antivirus solution and were downloaded by VirusTotal from the IP address provided:"
        IFS=$'\n' && for VIRUST_URLS_N in $(lynx -dump -force_html -nolist -accept_all_cookies -width=160 "https://www.virustotal.com/pt/ip-address/$TARGET_IP/information/" | grep -A10 'not detected by any antivirus' | grep '/' | column -t)
        do
                echo [*] $VIRUST_URLS_N
        done

        echo "[INFO] ------Alexa Rank SECTION------"
        echo "[INFO] Percent of Visitors Rank in Country:"
        IFS=$'\n' && for ALEXA_COUNTRY in $(lynx -dump -force_html -nolist -accept_all_cookies -width=160 "http://www.alexa.com/siteinfo/$TARGET_HOST" | grep -A5 'Percent of Visitors Rank in Country' | tail -5 | sed -e 's/^[ \t]*//' | sed -n -e 's/^.*Flag //p' | awk '{print$1,$2,$3,$4,$5}')
        do
                echo [*] $ALEXA_COUNTRY
        done

        echo "[INFO] Percent of Search Traffic:"
        IFS=$'\n' && for ALEXA_SEARCH in $(lynx -dump -force_html -nolist -accept_all_cookies -width=160 "http://www.alexa.com/siteinfo/$TARGET_HOST" | grep -A5 'Percent of Search Traffic' | sed -e 's/^[ \t]*//' | grep -o '[0-9].*\..*' | cut -d' ' -f2-50 | sed -e 's/^[ \t]*//')
        do
                echo [*] $ALEXA_SEARCH
        done

        echo "[INFO] Percent of Unique Visits:"
        IFS=$'\n' && for ALEXA_VISITS in $(lynx -dump -force_html -nolist -accept_all_cookies -width=160 "http://www.alexa.com/siteinfo/$TARGET_HOST" | grep -A5 'Percent of Unique Visits' | sed -e 's/^[ \t]*//' | grep -o '[0-9].*\..*' | awk '{print$2,$3}' | column -t)
        do
                echo [*] $ALEXA_VISITS
        done

        echo "[INFO] Total Sites Linking In:"
        IFS=$'\n' && for ALEXA_LINKING in $(lynx -dump -force_html -nolist -accept_all_cookies -width=160 "http://www.alexa.com/siteinfo/$TARGET_HOST" | grep -A9 'Total Sites Linking In' | sed -e 's/^[ \t]*//' | grep -o '[0-9].*\..*' | awk '{print$2,$3}' | head -5 | column -t) 
        do
                echo [*] $ALEXA_LINKING
        done

        echo [INFO] Useful links related to $TARGET_HOST - $TARGET_IP:
        echo "[*] https://www.virustotal.com/pt/ip-address/$TARGET_IP/information/" | tee -a URLs_$TARGET_HOST.txt
        echo "[*] https://www.hybrid-analysis.com/search?host=$TARGET_IP" | tee -a URLs_$TARGET_HOST.txt
        echo "[*] https://www.shodan.io/host/$TARGET_IP" | tee -a URLs_$TARGET_HOST.txt
        echo "[*] https://www.senderbase.org/lookup/?search_string=$TARGET_IP" | tee -a URLs_$TARGET_HOST.txt
        echo "[*] https://www.alienvault.com/open-threat-exchange/ip/$TARGET_IP" | tee -a URLs_$TARGET_HOST.txt
        echo "[*] http://pastebin.com/search?q=$TARGET_IP" | tee -a URLs_$TARGET_HOST.txt
        echo "[*] http://urlquery.net/search.php?q=$TARGET_IP" | tee -a URLs_$TARGET_HOST.txt
        echo "[*] http://www.alexa.com/siteinfo/$TARGET_HOST" | tee -a URLs_$TARGET_HOST.txt
        echo "[*] http://www.google.com/safebrowsing/diagnostic?site=$TARGET_HOST" | tee -a URLs_$TARGET_HOST.txt
        echo "[*] https://censys.io/ipv4/$TARGET_IP" | tee -a URLs_$TARGET_HOST.txt
	echo "[*] https://www.abuseipdb.com/check/$TARGET_IP" | tee -a URLs_$TARGET_HOST.txt
	echo "[*] https://urlscan.io/search/#$TARGET_IP" | tee -a URLs_$TARGET_HOST.txt
	echo "[*] https://github.com/search?q=$TARGET_IP&type=Code" | tee -a URLs_$TARGET_HOST.txt

        if [[ $TARGET_IP_ASN != "" ]]; then
                echo [INFO] Useful links related to $TARGET_IP_ASN - $TARGET_IP_BGP:
                TARGET_IP_ASN_TEMP=$(echo $TARGET_IP_ASN | cut -c3-12)
                echo "[*] http://www.google.com/safebrowsing/diagnostic?site=AS:$TARGET_IP_ASN_TEMP" | tee -a URLs_$TARGET_HOST.txt
                echo "[*] https://www.senderbase.org/lookup/?search_string=$TARGET_IP_BGP" | tee -a URLs_$TARGET_HOST.txt
                echo "[*] http://bgp.he.net/$TARGET_IP_ASN" | tee -a URLs_$TARGET_HOST.txt
                echo "[*] https://stat.ripe.net/$TARGET_IP_ASN" | tee -a URLs_$TARGET_HOST.txt
        fi

        rm -f URLs_$TARGET_HOST.txt $TARGET_DOMAIN.xml URLsExternal$TARGET_HOST.txt

	echo -e "`date +"%H:%M:%S %d/%m/%Y"`,$TARGET_IP,$TARGET" >> log.csv

        date '+[INFO] Date: %d/%m/%y | Time: %H:%M:%S'
        date_end=$(date +"%s")
        difference=$(($date_end-$date_begin))
        echo "[INFO] Total time: $(($difference / 60)) minute(s) and $(($difference %60)) second(s)"

        exit 0
fi
