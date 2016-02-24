#!/bin/bash

erase_temp_files(){
        echo -e "\n[ALERT] OK... Let's close"
        rm -f URLs_$TARGET_HOST.txt $TARGET_DOMAIN.xml URLsExternal$TARGET_HOST.txt
        exit 130
}

trap erase_temp_files SIGINT

clear

source config.sh

TARGET=$1

echo -e "\e[1;32m##################################################"
echo -e "#                  URLextractor                  #"
echo -e "# Information Gathering & Website Reconnaissance #"
echo -e "#              coded by eschultze                #"
echo -e "#                version - 0.1.8                 #"
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
        GEOIP=$(curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT http://freegeoip.net/csv/$EXTERNAL_IP) echo [*] External IP: $EXTERNAL_IP
        EXTERNAL_IP_CC=$(echo $GEOIP | cut -d',' -f2 | cut -d '"' -f2) && echo [*] CC: $EXTERNAL_IP_CC

        TRIES=0
        TRIES_MAX=6
        while [[ $EXTERNAL_IP_CC = "Try again later" ]] || [[ $EXTERNAL_IP_CC = "" ]]; do
                echo "[ALERT] Problem with Freegeoip detected... trying to reconnect with $CURL_TIMEOUT seconds timeout. Number of tries: $TRIES/$TRIES_MAX"
                TRIES=$((TRIES+1))
                GEOIP=`curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT http://freegeoip.net/csv/$EXTERNAL_IP`
                EXTERNAL_IP_CC=`echo $GEOIP | cut -d',' -f2 | cut -d '"' -f2`
                echo [*] Number of tries: $TRIES

                if [[ $TRIES -ge 6 ]]; then
                        echo "[ALERT] It seems Freegeoip is currently DOWN... exiting"
                        exit 1
                fi
        done

        EXTERNAL_IP_CN=$(echo $GEOIP | cut -d',' -f3 | cut -d '"' -f2) && echo [*] Contry: $EXTERNAL_IP_CN
        EXTERNAL_IP_RG=$(echo $GEOIP | cut -d',' -f4 | cut -d '"' -f2) && echo [*] RegionCode: $EXTERNAL_IP_RG
        EXTERNAL_IP_RN=$(echo $GEOIP | cut -d',' -f5 | cut -d '"' -f2) && echo [*] RegionName: $EXTERNAL_IP_RN
        EXTERNAL_IP_CITY=$(echo $GEOIP | cut -d',' -f6 | cut -d '"' -f2) && echo [*] City: $EXTERNAL_IP_CITY

        WHOIS_IP=`whois -h riswhois.ripe.net $EXTERNAL_IP | egrep "route|origin|descr" | head -4`
        EXTERNAL_IP_ASN=$(echo $WHOIS_IP | awk '{print$13}') && echo [*] ASN: $EXTERNAL_IP_ASN
        EXTERNAL_IP_BGP=$(echo $WHOIS_IP | awk '{print$11}') && echo [*] BGP_PREFIX: $EXTERNAL_IP_BGP
        EXTERNAL_IP_ISP=$(echo $WHOIS_IP | cut -d' ' -f15-28) && echo [*] ISP: $EXTERNAL_IP_ISP

        echo "[INFO] Possible abuse mails are:"
        for i in $(curl -L -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT "https://www.spamcop.net/sc?track=$EXTERNAL_IP" | grep -oE 'mailto:.*' | grep -v bait | cut -d':' -f2 | cut -d'"' -f1) ; do echo [*] $i; done
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

        GEOIP=$(curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT http://freegeoip.net/csv/$TARGET_HOST)
        TARGET_IP=$(echo $GEOIP | cut -d',' -f1 | cut -d '"' -f2)

        TRIES=0
        TRIES_MAX=6
        while [[ $TARGET_IP = "Try again later" ]] || [[ $TARGET_IP = "" ]]; do
                TRIES=$((TRIES+1))
                echo "[ALERT] Problem with Freegeoip detected... trying to reconnect with $CURL_TIMEOUT seconds timeout. Number of tries: $TRIES/$TRIES_MAX"
                GEOIP=`curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT http://freegeoip.net/csv/$TARGET_HOST`
                TARGET_IP=`echo $GEOIP | cut -d',' -f1 | cut -d '"' -f2`

                if [[ $TRIES -ge 6 ]]; then
                        echo "[ALERT] It seems Freegeoip is currently DOWN... exiting"
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

        TARGET_LOADB=$(host $TARGET_HOST | grep "has address" | wc -l)
        if [[ $TARGET_LOADB -ge 2 ]]; then
                echo "[ALERT] $TARGET_HOST has a load balancer for IPv4 with the following IPs:"
                for TARGET_LOADB_IP in $(host $TARGET_HOST | grep "has address" | cut -d' ' -f4)
                do
                        echo [*] $TARGET_LOADB_IP
                done
        else
                echo [INFO] NO load balancer detected at $TARGET_HOST...
        fi

        TARGET_DNS=$(dig -t SOA $TARGET_HOST | grep -A1 "AUTHORITY SECTION\|ANSWER SECTION" | awk '{print$5}' | sed '/^$/d') && echo [*] DNS servers: ${TARGET_DNS[@]}

        TARGET_SERVER=$(curl -A $CURL_UA -I -L --silent http://$TARGET_HOST/ | grep Server: | awk '{print $2;}' | awk 'NR==1') && echo [*] TARGET SERVER: $TARGET_SERVER
        TARGET_IP_CC=$(echo $GEOIP | cut -d',' -f2 | cut -d '"' -f2) && echo [*] CC: $TARGET_IP_CC
        TARGET_IP_CN=$(echo $GEOIP | cut -d',' -f3 | cut -d '"' -f2) && echo [*] Contry: $TARGET_IP_CN
        TARGET_IP_RG=$(echo $GEOIP | cut -d',' -f4 | cut -d '"' -f2) && echo [*] RegionCode: $TARGET_IP_RG
        TARGET_IP_RN=$(echo $GEOIP | cut -d',' -f5 | cut -d '"' -f2) && echo [*] RegionName: $TARGET_IP_RN
        TARGET_IP_CITY=$(echo $GEOIP | cut -d',' -f6 | cut -d '"' -f2) && echo [*] City: $TARGET_IP_CITY

        WHOIS_IP=`whois -h riswhois.ripe.net $TARGET_IP | egrep "route|origin|descr" | head -4`
        TARGET_IP_ASN=$(echo $WHOIS_IP | awk '{print$13}') && echo [*] ASN: $TARGET_IP_ASN
        TARGET_IP_BGP=$(echo $WHOIS_IP | awk '{print$11}') && echo [*] BGP_PREFIX: $TARGET_IP_BGP
        TARGET_IP_ISP=$(echo $WHOIS_IP | cut -d' ' -f15-28) && echo [*] ISP: $TARGET_IP_ISP
        
        echo "[INFO] Possible abuse mails are:"
        for TEMP_MAIL in $(curl -L -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT "https://www.spamcop.net/sc?track=$TARGET_IP" | grep -oE 'mailto:.*' | grep -v bait | cut -d':' -f2 | cut -d'"' -f1)
        do
                echo [*] $TEMP_MAIL
        done

        PAC_TEST=$(curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT $TARGET | grep -o FindProxyForURL)
        if [[ "$PAC_TEST" = "FindProxyForURL" ]]; then
                PAC_PROXY=$(curl -A $CURL_UA --silent --connect-timeout $CURL_TIMEOUT $TARGET | grep PROXY | grep -oE "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):([0-9]{1,5})")
                echo "[ALERT] PAC (Proxy Auto Configuration) file found with possible PROXY: $PAC_PROXY"
        else
                echo "[INFO] NO PAC (Proxy Auto Configuration) file FOUND"
        fi

        TARGET_PATH=$(echo $TARGET | cut -d'/' -f4-20)
        FOLDER_COUNT=$(echo $TARGET_PATH | tr "/" " " | wc -w)
        if [[ $FOLDER_COUNT -ge 2 ]]; then
                echo -e "[INFO] Satus code \t Folders "
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
                for TEMP_ROBOTS in $(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT "http://$TARGET_HOST/robots.txt" | grep -oE "^(All.*|Dis.*).*" | cut -d' ' -f2) 
                do
                        ROBOTS_CODE=`curl -L -A $CURL_UA --write-out "%{http_code}\n" --silent --connect-timeout $CURL_TIMEOUT --output /dev/null "http://$TARGET_HOST$TEMP_ROBOTS"`
                        if [[ $ROBOTS_CODE =~ ^2 ]] || [[ $ROBOTS_CODE =~ ^3 ]]; then
                                echo "[*] $ROBOTS_CODE - http://$TARGET_HOST$TEMP_ROBOTS"
                                echo http://$TARGET_HOST$TEMP_ROBOTS >> URLs_$TARGET_HOST.txt
                        fi
                done
        fi

        PASS1=$(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT $TARGET | grep -i 'user\|pass\|root\|admin')
        PASS2=$(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT http://$TARGET_HOST/ | grep -i 'user\|pass\|root\|admin')
        PASS3=$(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT http://$TARGET_IP/ | grep -i 'user\|pass\|root\|admin')

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
        else
                MD3=$(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT "http://$TARGET_IP/" | md5sum | cut -d' ' -f1)        
                if [[ $MD1 = $MD3 ]]; then
                        echo "[INFO] SAME content in http://$TARGET_HOST/ AND http://$TARGET_IP/"
                        URL_ARRAY=($TARGET)
                else
                        URL_ARRAY=($TARGET http://$TARGET_IP/)
                fi
        fi
        
        for TEMP_ARRAY in $(echo ${URL_ARRAY[*]})
        do
                echo [INFO] External links from $TEMP_ARRAY: && for TEMP_LINK in $(curl -A $CURL_UA -L --silent --connect-timeout $CURL_TIMEOUT $TEMP_ARRAY | grep -o '<a href=['"'"'"][^"'"'"']*['"'"'"]' | sed -e 's/^<a href=["'"'"']//' -e 's/["'"'"']$//' | grep -E ^http | sort | uniq)
                do
                        echo [*] $TEMP_LINK | grep -v $TARGET_HOST | tee -a URLsExternal$TARGET_HOST.txt
                done
        done

        echo "[INFO] Starting FUZZing in http://$TARGET_HOST/FUzZzZzZzZz..."
        cat fuzz | head -$FUZZ_LIMIT | while read DIR
        do
                FUZZ_CODE=`curl -L -A $CURL_UA --write-out "%{http_code}\n" --silent --connect-timeout $CURL_TIMEOUT --output /dev/null "http://$TARGET_HOST/$DIR"`
                if [[ $FUZZ_CODE =~ ^2 ]] || [[ $FUZZ_CODE =~ ^3 ]]; then
                        echo "[*] $FUZZ_CODE - http://$TARGET_HOST/$DIR"
                        echo http://$TARGET_HOST/$DIR >> URLs_$TARGET_HOST.txt
                fi
        done

        HOST_COUNT=$(echo $TARGET_HOST | tr "." " " | wc -w)
        if [[ $HOST_COUNT -ge 3 ]]; then
                CUT_TEMP=$(echo $HOST_COUNT -1 | bc)
                TARGET_DOMAIN=$(echo $TARGET_HOST | cut -d'.' -f$CUT_TEMP-$HOST_COUNT)
        else
                TARGET_DOMAIN=$TARGET_HOST
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

        if [[ $TARGET_IP_ASN != "" ]]; then
                echo [INFO] Useful links related to $TARGET_IP_ASN - $TARGET_IP_BGP:
                TARGET_IP_ASN_TEMP=$(echo $TARGET_IP_ASN | cut -c3-12)
                echo "[*] http://www.google.com/safebrowsing/diagnostic?site=AS:$TARGET_IP_ASN_TEMP" | tee -a URLs_$TARGET_HOST.txt
                echo "[*] https://www.senderbase.org/lookup/?search_string=$TARGET_IP_BGP" | tee -a URLs_$TARGET_HOST.txt
                echo "[*] http://bgp.he.net/$TARGET_IP_ASN" | tee -a URLs_$TARGET_HOST.txt
                echo "[*] https://stat.ripe.net/$TARGET_IP_ASN" | tee -a URLs_$TARGET_HOST.txt
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

        rm -f URLs_$TARGET_HOST.txt $TARGET_DOMAIN.xml URLsExternal$TARGET_HOST.txt

        date '+[INFO] Date: %d/%m/%y | Time: %H:%M:%S'
        date_end=$(date +"%s")
        difference=$(($date_end-$date_begin))
        echo "[INFO] Total time: $(($difference / 60)) minutes and $(($difference %60)) seconds"

        exit 0
fi