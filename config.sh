#!/bin/bash

CURL_TIMEOUT=15 #timeout in --connect-timeout
CURL_UA=Mozilla #user-agent (keep it simple)
INTERNAL=NO #YES OR NO (show internal network info)
URLVOID_KEY= #using API from http://www.urlvoid.com/
FUZZ_LIMIT=10 #how many lines it will read from fuzz file
OPEN_TARGET_URLS=NO #open found URLs at the end of script
OPEN_EXTERNAL_LINKS=NO #open external links (frames) at the end of script
