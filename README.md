# LDAP Domain Recon & Kerberoasting Automation

Active Directory ortamlarında yetkili (authenticated) LDAP enumeration, Kerberoasting/AS-REP roasting saldırı yüzeyi taraması ve elde edilen hash'lerin kırılmasını tek bir script üzerinden otomatize eden bir recon aracı.

> ⚠️ **Yasal Uyarı:** Bu araç yalnızca yazılı izniniz olan ortamlarda (kendi lab'iniz, CTF, veya kapsamı açıkça belirtilmiş bir penetration test/bug bounty engagement'ı) kullanılmalıdır. Yetkisiz sistemlerde kullanım yasa dışıdır.

## Özellikler

- LDAP üzerinden domain enumeration (kullanıcılar, gruplar, bilgisayarlar)
- Kerberoastable ve AS-REP roastable hesapların otomatik tespiti
- Opsiyonel Kerberoasting / AS-REP Roasting saldırı zinciri
- Opsiyonel hashcat ile hash kırma (TGS-RC4, TGS-AES128, TGS-AES256, AS-REP)

## Gereksinimler (Tools)

Script'in çalışabilmesi için aşağıdaki araçların sistemde kurulu ve `PATH` içinde erişilebilir olması gerekir:

| Araç | Amaç |
|---|---|
| `ldapsearch` | LDAP üzerinden kullanıcı/grup/bilgisayar enumeration |
| `impacket-GetUserSPNs` | Kerberoastable hesapların (SPN'li) tespiti ve TGS hash çıkarımı |
| `impacket-GetNPUsers` | Pre-authentication devre dışı hesaplar için AS-REP roasting |
| `hashcat` | Elde edilen Kerberos hash'lerinin (opsiyonel) kırılması |

## Kurulum

```bash
git clone https://github.com/acivik/demorecon.git
cd demorecon
chmod +x ldapdemorecon.sh
```

Impacket araçlarının kurulu olduğundan emin olun:

```bash
pip install impacket --break-system-packages
```

## Kullanım

```bash
./ldapdemorecon.sh -d <domain.local> -i <ipaddress> -u <username> -p <password>
```

### Örnek

```bash
./ldapdemorecon.sh -d corp.local -i 10.10.10.5 -u jdoe -p 'P@ssw0rd123'
```

## Çıktılar

Script çalıştığında recon sonuçları aşağıdaki dizin yapısında saklanır:

```
📁 Users:        ./ldap_dump/users.txt
📁 Groups:       ./ldap_dump/groups.txt
📁 Computers:    ./ldap_dump/computers.txt
📁 Kerberoast:   ./ldap_dump/kerberoastable.txt
📁 AS-REP:       ./ldap_dump/aspreproastable.txt
```

## Etkileşimli Adımlar

Recon tamamlandıktan sonra script iki noktada onay ister:

### 1. Kerberos Saldırıları

```
Do you want to attack kerberos (y/n)
```

`y` seçilirse, tespit edilen kerberoastable ve AS-REP roastable hesaplar için hash extraction gerçekleştirilir:

```
📁 ./kerberos/kerberoasting_hashes.txt
📁 ./kerberos/asreproasting_hashes.txt
```

### 2. Hash Kırma

```
Do you want to crack hashes (y/n)
```

`y` seçilirse, wordlist girmeniz bekleniyor. Elde edilen hash'ler hashcat ile (mod'a göre TGS-RC4 / AES128 / AES256 / AS-REP) kırılmaya çalışılır ve sonuçlar kaydedilir:

```
📁 ./hashes/tgs23.hashes_cracked
📁 ./hashes/tgs17.hashes_cracked
📁 ./hashes/tgs18.hashes_cracked
📁 ./hashes/asrep23.hashes_cracked
```

## Dizin Yapısı Özeti

```
.
├── ldapdemorecon.sh
├── ldap_dump/
│   ├── users.txt
│   ├── groups.txt
│   ├── computers.txt
│   ├── kerberoastable.txt
│   └── aspreproastable.txt
├── kerberos/
│   ├── kerberoasting_hashes.txt
│   └── asreproasting_hashes.txt
└── hashes/
    ├── tgs23.hashes_cracked
    ├── tgs17.hashes_cracked
    ├── tgs18.hashes_cracked
    └── asrep23.hashes_cracked
```
