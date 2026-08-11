Tools
  ldapsearch
  impacket-GetUserSPNs
  impacket-GetNPUsers
  hashcat
  
Usage
  `./ldapdemorecon.sh -d <domain.local> -i <ipaddress> -u <username> -p <password>`

Saving results like this
📁 Users: ./ldap_dump/users.txt
📁 Groups: ./ldap_dump/groups.txt
📁 Computers: ./ldap_dump/computers.txt
📁 Kerberoast: ./ldap_dump/kerberoastable.txt
📁 AS-REP: ./ldap_dump/aspreproastable.txt

If you want kerberos attack press y then
📁: ./kerberos/kerberoasting_hashes.txt
📁: ./kerberos/asreproasting_hashes.txt

If you want to crack hashes press y then
📁 Result Saved:$ENDCOLOR ./hashes/tgs23.hashes_cracked
📁 Result Saved:$ENDCOLOR ./hashes/tgs17.hashes_cracked
📁 Result Saved:$ENDCOLOR ./hashes/tgs18.hashes_cracked
📁 Result Saved:$ENDCOLOR ./hashes/asrep23.hashes_cracked
