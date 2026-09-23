OPEN PORT EXPOSURE ANALYSIS
Authorized Lab Assessment using Kali Linux and Metasploitable2
Evidence-based reconnaissance, service enumeration, exposure analysis and risk documentation
Assessment date: 22 September 2026
Assessment scope: Authorized isolated laboratory environment only.
Attacker/security-analysis host: Kali Linux
Target: Metasploitable2 — 192.168.1.4
Known Ubuntu host in the lab: 192.168.1.5
1. Executive Summary
This report documents the open-port exposure assessment performed in an authorized, isolated laboratory using Kali Linux against a Metasploitable2 target at 192.168.1.4. The assessment started with Nmap service discovery and then used targeted Nmap NSE scripts, WhatWeb, rpcinfo, showmount, dig and a controlled NFS mount to determine what services were exposed and what configuration information could be established from evidence.
The assessment confirmed multiple exposed services. Important findings included anonymous FTP login, unencrypted Telnet, legacy SSH cryptographic algorithms, SMBv1 and anonymous read/write access reported for specific SMB shares, NFS exporting the root filesystem to '*', successful read/write NFS mounting from the authorized Kali host, DNS version disclosure and recursion availability, an exposed legacy MySQL service, and HTTP/WebDAV/PHP version information disclosure.
The report deliberately separates confirmed evidence from assumptions. A service version being old does not, by itself, prove that a specific vulnerability is exploitable. Likewise, an NFS export being present does not automatically prove every possible filesystem operation; in this assessment, the successful read/write mount provides additional evidence. No destructive changes or exploitation were required to establish the principal findings.
2. Project Problem Statement
Open network ports expose services that may become attack targets. The project objective is to identify exposed services, determine what information and access they provide, assess unnecessary or weak configurations, correlate external/reconnaissance-style observations with authorized Nmap analysis, document evidence, and recommend hardening.
3. Objectives
•	Identify open TCP ports on the authorized Metasploitable2 target.
•	Identify the services and versions associated with those ports.
•	Use safe service-enumeration techniques to determine additional exposure.
•	Document evidence rather than assuming that an old version is automatically exploitable.
•	Identify unnecessary, legacy, overly broad, or weakly configured services.
•	Record reproducible commands and outputs for a final assessment report.
•	Provide remediation/hardening recommendations and establish a basis for before/after rescanning.
4. Lab Environment and Scope
Component	Value
Security-analysis host	Kali Linux
Target	Metasploitable2
Target IP	192.168.1.4
Known Ubuntu host	192.168.1.5
Network type	Authorized lab / isolated testing environment
Primary scanner	Nmap 7.99
Web fingerprinting	WhatWeb
RPC/NFS tools	rpcinfo, showmount, mount
DNS analysis	Nmap NSE, dig
Packet capture	Wireshark was considered but deferred because it was slow; no Wireshark finding is claimed in this report.
5. Methodology
The assessment followed a progressive evidence-based workflow. First, the target was identified and a baseline Nmap scan was performed. Service/version detection was then used to inventory exposed services. Individual services were selected for targeted NSE enumeration and manual protocol-level checks. Where a finding required stronger evidence, a controlled validation was performed without modifying the target.
1.	Baseline port discovery.
2.	Service and version identification with Nmap -sV.
3.	Web fingerprinting with WhatWeb.
4.	HTTP title, header and method enumeration.
5.	FTP anonymous-login and system-information checks, followed by a manual anonymous login test.
6.	SMB protocol/OS discovery and share enumeration.
7.	NFS/RPC enumeration using rpcinfo and showmount.
8.	Controlled NFS mount validation, followed by clean unmounting.
9.	Telnet encryption capability check.
10.	SSH algorithm enumeration.
11.	DNS NSID/version disclosure and controlled recursive DNS query.
12.	MySQL protocol/service information enumeration.
6. Baseline Nmap Scan
nmap -sV 192.168.1.4
Observed result:
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-22 09:30 -0400
Nmap scan report for 192.168.1.4
Host is up.
Not shown: 977 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
53/tcp   open  domain      ISC BIND 9.4.2
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp  open  exec?
513/tcp  open  login
514/tcp  open  tcpwrapped
1099/tcp open  java-rmi    GNU Classpath grmiregistry
1524/tcp open  bindshell   Metasploitable root shell
2049/tcp open  nfs         2-4 (RPC #100003)
2121/tcp open  ftp         ProFTPD 1.3.1
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  PostgreSQL 8.3.0 - 8.3.7
5900/tcp open  vnc         VNC (protocol 3.3)
6000/tcp open  X11         (access denied)
6667/tcp open  irc         UnrealIRCd
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
MAC Address: 08:00:27:1B:91:11 (Oracle VirtualBox virtual NIC)
Service Info: Hosts: metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) in 88.03 seconds
Evidence/interpretation: The baseline scan identified 23 open TCP ports in the default 1000-port scan and 977 closed TCP ports. The exact Nmap output above is the evidence used for the service inventory. No claim is made here that every listed service is exploitable.
7. HTTP / Web Service Analysis — Port 80
7.1 WhatWeb fingerprinting
whatweb http://192.168.1.4
http://192.168.1.4 [200 OK] Apache[2.2.8], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.2.8 (Ubuntu) DAV/2], IP[192.168.1.4], PHP[5.2.4-2ubuntu5.10], Title[Metasploitable2 - Linux], WebDAV[2], X-Powered-By[PHP/5.2.4-2ubuntu5.10]
Confirmed observations: HTTP returned 200 OK; Apache 2.2.8 was fingerprinted; Ubuntu Linux and PHP 5.2.4-2ubuntu5.10 were disclosed; the page title identifies Metasploitable2; WebDAV/DAV was detected; and X-Powered-By exposed the PHP version.
Important limitation: WebDAV detection does not by itself prove that dangerous write methods are enabled, and an old version does not by itself prove exploitability.
7.2 HTTP title
nmap --script http-title -p 80 192.168.1.4
80/tcp open http
|_http-title: Metasploitable2 - Linux
7.3 HTTP headers
nmap --script http-headers -p 80 192.168.1.4
80/tcp open http
Server: Apache/2.2.8 (Ubuntu) DAV/2
X-Powered-By: PHP/5.2.4-2ubuntu5.10
Connection: close
Content-Type: text/html
Evidence/interpretation: The HTTP headers independently corroborated the Apache/PHP fingerprint and showed version disclosure through Server and X-Powered-By.
7.4 HTTP methods
nmap --script http-methods -p 80 192.168.1.4
80/tcp open http
| http-methods:
|   Supported Methods: GET HEAD POST OPTIONS
Evidence/interpretation: GET, HEAD, POST and OPTIONS were reported. PUT and DELETE were not reported by this enumeration. Therefore, the assessment does not claim that arbitrary WebDAV write methods are enabled.
8. FTP Analysis — Port 21
8.1 FTP NSE
nmap --script ftp-anon,ftp-syst -p 21 192.168.1.4
21/tcp open ftp
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
|      Connected to 192.168.1.3
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
8.2 Manual validation
ftp 192.168.1.4
220 (vsFTPd 2.3.4)
Name: anonymous
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||6500|).
150 Here comes the directory listing.
226 Directory send OK.
Evidence/interpretation: Anonymous FTP authentication was successfully demonstrated. The directory-listing request completed but returned no filenames in the captured output. The evidence therefore does not claim that anonymous users can download files.
Risk/remediation: Disable anonymous FTP unless explicitly required; restrict filesystem permissions; prefer SFTP/FTPS where appropriate; and restrict FTP access with firewall rules.
9. SMB Analysis — Ports 139 and 445
9.1 SMB protocol and OS discovery
nmap --script smb-os-discovery,smb-protocols -p 139,445 192.168.1.4
139/tcp open netbios-ssn
445/tcp open microsoft-ds
Host script results:
| smb-protocols:
|   dialects:
|_    NT LM 0.12 (SMBv1) [dangerous, but default]
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: metasploitable
|   NetBIOS computer name:
|   Domain name: localdomain
|   FQDN: metasploitable.localdomain
|_  System time: 2026-09-22T08:11:12-04:00
Evidence/interpretation: SMBv1 was explicitly reported. The scan also disclosed Samba 3.0.20-Debian and host/domain naming information. These are configuration/information-disclosure findings, not proof of a particular exploit.
9.2 SMB share enumeration
nmap --script smb-enum-shares -p 139,445 192.168.1.4
\\192.168.1.4\ADMIN$:
  Type: STYPE_IPC
  Comment: IPC Service (metasploitable server (Samba 3.0.20-Debian))
  Anonymous access: <none>

\\192.168.1.4\IPC$:
  Type: STYPE_IPC
  Comment: IPC Service (metasploitable server (Samba 3.0.20-Debian))
  Anonymous access: READ/WRITE

\\192.168.1.4\opt:
  Type: STYPE_DISKTREE
  Anonymous access: <none>

\\192.168.1.4\print$:
  Type: STYPE_DISKTREE
  Comment: Printer Drivers
  Anonymous access: <none>

\\192.168.1.4\tmp:
  Type: STYPE_DISKTREE
  Comment: oh noes!
  Anonymous access: READ/WRITE
Evidence/interpretation: The Nmap output reports anonymous READ/WRITE for IPC$ and tmp. IPC$ is a special IPC share and should not be interpreted as arbitrary file-system read/write. The tmp share is a disk share, so its reported anonymous read/write access is a significant access-control weakness.
Risk/remediation: Disable guest/anonymous SMB access unless explicitly required, review share and filesystem permissions, disable SMBv1, upgrade Samba, and restrict ports 139/445 to trusted networks.
10. NFS / RPC Analysis — Ports 111 and 2049
10.1 Initial NFS NSE
nmap --script nfs-showmount,nfs-ls -p 2049 192.168.1.4
2049/tcp open nfs
MAC Address: 08:00:27:1B:91:11 (Oracle VirtualBox virtual NIC)
Nmap done: 1 IP address (1 host up)
Evidence/interpretation: This scan confirmed NFS listening on TCP/2049 but did not itself return export entries. Therefore, no export was claimed at this stage.
10.2 RPC service inventory
rpcinfo -p 192.168.1.4
program vers proto   port  service
100000    2   tcp    111  portmapper
100000    2   udp    111  portmapper
100024    1   udp  46361  status
100024    1   tcp  60046  status
100003    2   udp   2049  nfs
100003    3   udp   2049  nfs
100003    4   udp   2049  nfs
100021    1   udp  49234  nlockmgr
100021    3   udp  49234  nlockmgr
100021    4   udp  49234  nlockmgr
100003    2   tcp   2049  nfs
100003    3   tcp   2049  nfs
100003    4   tcp   2049  nfs
100021    1   tcp  57157  nlockmgr
100021    3   tcp  57157  nlockmgr
100021    4   tcp  57157  nlockmgr
100005    1   udp  49798  mountd
100005    1   tcp  48304  mountd
100005    2   udp  49798  mountd
100005    2   tcp  48304  mountd
100005    3   udp  49798  mountd
100005    3   tcp  48304  mountd
Evidence/interpretation: RPC registration showed portmapper, NFS v2/v3/v4, lock manager and mountd services. The output also shows dynamic RPC ports for status, lock management and mountd.
10.3 NFS export discovery
showmount -e 192.168.1.4
Export list for 192.168.1.4:
/ *
Evidence/interpretation: The root filesystem '/' is exported and '*' is the client specification. This demonstrates a broadly permitted root export.
10.4 Controlled NFS mount validation
sudo mount -t nfs 192.168.1.4:/ /mnt
Created symlink '/run/systemd/system/remote-fs.target.wants/rpc-statd.service' → '/usr/lib/systemd/system/rpc-statd.service'.
mount | grep 192.168.1.4
192.168.1.4:/ on /mnt type nfs (rw,relatime,vers=3,rsize=262144,wsize=262144,namlen=255,hard,fatal_neterrors=none,proto=tcp,timeo=600,retrans=2,sec=sys,mountaddr=192.168.1.4,mountvers=3,mountport=49798,mountproto=udp,local_lock=none,addr=192.168.1.4)
Evidence/interpretation: The export was successfully mounted from Kali. The mount output explicitly contains 'rw' and 'vers=3', so the authorized client mounted the exported root filesystem using NFSv3 with read/write access. No files were created, deleted or modified as part of the validation.
Remediation: Do not export the root filesystem. Restrict exports to explicitly authorized hosts/networks, export only required directories, apply least-privilege export options, and review NFS/RPC exposure. After testing, the export should be unmounted with 'sudo umount /mnt'.
11. Telnet Analysis — Port 23
nmap --script telnet-encryption -p 23 192.168.1.4
23/tcp open telnet
| telnet-encryption:
|_  Telnet server does not support encryption
nmap -sV -p 23 192.168.1.4
23/tcp open telnet Linux telnetd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Evidence/interpretation: The server does not support Telnet encryption. This establishes an insecure legacy remote-administration configuration. No password guessing or brute-force activity was performed.
Remediation: Disable Telnet where not required and use SSH for remote administration. Restrict administrative services to trusted management networks.
12. SSH Analysis — Port 22
nmap --script ssh2-enum-algos -p 22 192.168.1.4
22/tcp open ssh
kex_algorithms:
  diffie-hellman-group-exchange-sha256
  diffie-hellman-group-exchange-sha1
  diffie-hellman-group14-sha1
  diffie-hellman-group1-sha1
server_host_key_algorithms:
  ssh-rsa
  ssh-dss
encryption_algorithms:
  aes128-cbc
  3des-cbc
  blowfish-cbc
  cast128-cbc
  arcfour128
  arcfour256
  arcfour
  aes192-cbc
  aes256-cbc
  rijndael-cbc@lysator.liu.se
  aes128-ctr
  aes192-ctr
  aes256-ctr
mac_algorithms:
  hmac-md5
  hmac-sha1
  umac-64@openssh.com
  hmac-ripemd160
  hmac-ripemd160@openssh.com
  hmac-sha1-96
  hmac-md5-96
compression_algorithms:
  none
  zlib@openssh.com
nmap -sV -p 22 192.168.1.4
22/tcp open ssh OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Evidence/interpretation: The SSH server exposes multiple legacy cryptographic algorithms, including SHA-1/DH variants, ssh-dss, CBC ciphers, RC4-family ciphers, 3DES, and MD5/SHA-1-based MACs. This is a legacy cryptographic configuration finding. It is not, by itself, proof of a specific exploitable vulnerability.
Remediation: Upgrade OpenSSH and the underlying operating system where appropriate, remove obsolete algorithms, and enforce a modern cryptographic policy.
13. DNS Analysis — Port 53
nmap --script dns-recursion,dns-nsid -p 53 192.168.1.4
53/tcp open domain
| dns-nsid:
|_  bind.version: 9.4.2
Evidence/interpretation: BIND version 9.4.2 is disclosed. The NSE result did not itself report recursion, so recursion was not claimed from that result alone.
13.1 Controlled recursion test
dig @192.168.1.4 google.com
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 26633
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 1
;; ANSWER SECTION:
google.com. 300 IN A 142.251.221.206
;; SERVER: 192.168.1.4#53(192.168.1.4) (UDP)
Evidence/interpretation: The query returned NOERROR and an A record for google.com. The response includes 'ra' (Recursion Available), while the query included 'rd' (Recursion Desired). This confirms that recursion was available to the authorized Kali client. It does not, by itself, prove that the resolver is reachable from the public Internet.
Remediation: Restrict recursive DNS queries to authorized internal clients/networks, minimize version disclosure where appropriate, and upgrade/secure the DNS software.
14. MySQL Analysis — Port 3306
nmap --script mysql-info -p 3306 192.168.1.4
3306/tcp open mysql
| mysql-info:
|   Protocol: 10
|   Version: 5.0.51a-3ubuntu5
|   Thread ID: 13
|   Capabilities flags: 43564
|   Some Capabilities: Support41Auth, SupportsTransactions, Speaks41ProtocolNew, LongColumnFlag, SwitchToSSLAfterHandshake, SupportsCompression, ConnectWithDatabase
|   Status: Autocommit
|_  Salt: 3Pw(\yk.BBaDlw0&lpoZ
Evidence/interpretation: MySQL 5.0.51a-3ubuntu5 is directly exposed and discloses its version during the protocol handshake. The presence of 'SwitchToSSLAfterHandshake' indicates SSL-related protocol capability, but does not prove that encryption is required for every connection.
Remediation: Upgrade the database software, restrict port 3306 to authorized application/management hosts, and configure encrypted connections where required.
15. Findings Summary
Port(s)	Service	Confirmed evidence	Assessment / exposure
21/tcp	FTP	Anonymous login returned FTP 230; plaintext control/data reported	Anonymous access and plaintext transport
22/tcp	SSH	OpenSSH 4.7p1; multiple legacy algorithms	Legacy cryptographic configuration
23/tcp	Telnet	Linux telnetd; encryption script says encryption unsupported	Unencrypted legacy remote administration
53/tcp	DNS	BIND 9.4.2 disclosed; dig returned NOERROR with ra	Version disclosure and recursion available to lab client
80/tcp	HTTP	Apache 2.2.8, PHP 5.2.4, DAV/2, WebDAV fingerprint; GET/HEAD/POST/OPTIONS	Legacy software/version disclosure; WebDAV detected
139/445	SMB	SMBv1; Samba 3.0.20-Debian; tmp and IPC$ reported anonymous READ/WRITE	Legacy protocol and weak access-control exposure
111/2049 + RPC	NFS/RPC	/ exported to *; successful NFSv3 rw mount	Overly broad root filesystem exposure with read/write mount
3306/tcp	MySQL	MySQL 5.0.51a-3ubuntu5 handshake	Legacy database exposed to network
16. Services Identified but Not Yet Deeply Analyzed
The baseline Nmap scan identified additional services. They are recorded here so that they are not accidentally omitted from the assessment:
Port	Service / version reported by baseline scan	Status in this report
25/tcp	Postfix smtpd	Identified; not yet deeply enumerated
512/tcp	exec?	Identified; not yet deeply enumerated
513/tcp	login	Identified; not yet deeply enumerated
514/tcp	tcpwrapped	Identified; not yet deeply enumerated
1099/tcp	GNU Classpath grmiregistry	Identified; not yet deeply enumerated
1524/tcp	Metasploitable root shell	Identified by Nmap; not interacted with
2121/tcp	ProFTPD 1.3.1	Identified; not yet deeply enumerated
5432/tcp	PostgreSQL 8.3.0–8.3.7	Identified; detailed enumeration not yet performed
5900/tcp	VNC protocol 3.3	Identified; not yet deeply enumerated
6000/tcp	X11; access denied	Identified; Nmap reported access denied
6667/tcp	UnrealIRCd	Identified; not yet deeply enumerated
8009/tcp	AJP13 / Apache Jserv	Identified; not yet deeply enumerated
8180/tcp	Apache Tomcat/Coyote JSP engine 1.1	Identified; not yet deeply enumerated
Evidence/interpretation: This section is intentionally included to avoid implying that the eight detailed findings represent every open service. The baseline scan found 23 open TCP ports; only the services supported by collected evidence have been given detailed conclusions.
17. Evidence and Claim Discipline
•	Open port ≠ automatically vulnerable.
•	A detected version ≠ proof of exploitability.
•	WebDAV detection ≠ proof that PUT/DELETE or arbitrary write operations are enabled.
•	Anonymous FTP login ≠ proof that files can be downloaded; the observed directory listing returned no filenames.
•	NFS export listing ≠ proof of access by every possible operation; in this lab, successful rw mounting supplied stronger evidence.
•	DNS recursion available to the Kali host ≠ proof of an Internet-wide open resolver.
•	SMB IPC$ READ/WRITE should not be interpreted as unrestricted filesystem access; the tmp disk share is the stronger access-control observation.
•	No brute-force, destructive modification, or exploit execution was required for the findings documented here.
18. Wireshark Status
Wireshark was considered for packet-level correlation, but the user chose to defer it because packet capture/analysis was slow. Therefore, this report does not claim any Wireshark-derived vulnerability or packet evidence. The current findings are based on the actual Kali command outputs collected above.
19. What Was Not Assumed
•	No public-Internet exposure was assumed. The tested target was the authorized lab IP 192.168.1.4.
•	No exploitability was inferred solely from software age/version.
•	No anonymous SMB access was assumed beyond the shares explicitly reported by Nmap.
•	No dangerous WebDAV method was assumed beyond the methods explicitly enumerated.
•	No NFS file modification was performed to prove the finding.
•	No credential compromise was claimed for Telnet, FTP, SSH or database services.
•	No brute-force testing was performed.
•	No conclusion was made about the untested services beyond what the baseline Nmap output explicitly identified.
20. Recommended Hardening Plan
Priority area	Recommended action	Verification
NFS	Remove root '/' export; restrict clients; export only required directories; least privilege	showmount -e and NFS rescan
SMB	Disable SMBv1; remove anonymous/guest write access; review share permissions; restrict 139/445	smb-protocols and smb-enum-shares
Telnet	Disable Telnet; use SSH	Nmap port 23 rescan
FTP	Disable anonymous FTP unless required; prefer SFTP/FTPS; restrict port 21	ftp-anon and service rescan
SSH	Upgrade OpenSSH; disable obsolete algorithms; use modern crypto policy	ssh2-enum-algos
DNS	Restrict recursion; minimize version disclosure; upgrade BIND	dig + Nmap DNS NSE
HTTP	Upgrade Apache/PHP; review WebDAV; minimize version headers; restrict unnecessary methods	WhatWeb/http-headers/http-methods
MySQL	Upgrade database; restrict 3306 to authorized hosts; use encryption where required	mysql-info and firewall validation
21. Suggested Before/After Validation
For the later hardening phase, repeat the baseline scan and the same targeted checks. The report should compare:
•	Number of open ports before and after hardening.
•	Which services were intentionally disabled.
•	Whether anonymous FTP is still accepted.
•	Whether SMBv1 and anonymous share access remain.
•	Whether NFS '/' is still exported and whether broad client access remains.
•	Whether Telnet port 23 is closed.
•	Whether legacy SSH algorithms have been removed.
•	Whether DNS recursion is restricted.
•	Whether unnecessary database exposure remains.
•	Whether HTTP information disclosure and unnecessary WebDAV functionality remain.
22. Conclusion
The Kali-based assessment demonstrated that the Metasploitable2 target exposes a large number of network services. Targeted enumeration converted the initial list of open ports into specific, evidence-backed configuration findings. The strongest demonstrated exposures were the broad NFS root export with successful read/write mounting, SMBv1 and reported anonymous read/write access on the tmp share, anonymous FTP login, unencrypted Telnet, legacy SSH cryptographic algorithms, DNS recursion availability, and legacy web/database service configurations.
The assessment also demonstrates an important security-analysis principle: the presence of an old service version should be documented as a version/configuration finding unless a separate authoritative vulnerability analysis establishes a specific vulnerability. The next phase should apply hardening to the authorized lab target and repeat the same scans to produce a before/after comparison.
23. Command Reference — Reproducibility
nmap -sV 192.168.1.4
whatweb http://192.168.1.4
nmap --script http-title -p 80 192.168.1.4
nmap --script http-headers -p 80 192.168.1.4
nmap --script http-methods -p 80 192.168.1.4
nmap --script ftp-anon,ftp-syst -p 21 192.168.1.4
ftp 192.168.1.4  (manual anonymous-login validation)
nmap --script smb-os-discovery,smb-protocols -p 139,445 192.168.1.4
nmap --script smb-enum-shares -p 139,445 192.168.1.4
nmap --script nfs-showmount,nfs-ls -p 2049 192.168.1.4
rpcinfo -p 192.168.1.4
showmount -e 192.168.1.4
sudo mount -t nfs 192.168.1.4:/ /mnt
mount | grep 192.168.1.4
sudo umount /mnt
nmap --script telnet-encryption -p 23 192.168.1.4
nmap -sV -p 23 192.168.1.4
nmap --script ssh2-enum-algos -p 22 192.168.1.4
nmap -sV -p 22 192.168.1.4
nmap --script dns-recursion,dns-nsid -p 53 192.168.1.4
dig @192.168.1.4 google.com
nmap --script mysql-info -p 3306 192.168.1.4
24. Final Evidence Checklist
•	Baseline Nmap service inventory — collected.
•	WhatWeb HTTP fingerprint — collected.
•	HTTP title — collected.
•	HTTP headers — collected.
•	HTTP methods — collected.
•	FTP anonymous login evidence — collected.
•	SMBv1 and Samba identification — collected.
•	SMB share/anonymous access evidence — collected.
•	RPC/NFS program inventory — collected.
•	NFS export list — collected.
•	Successful NFS read/write mount evidence — collected.
•	Telnet no-encryption evidence — collected.
•	SSH algorithm enumeration — collected.
•	DNS version disclosure — collected.
•	DNS recursion evidence using dig — collected.
•	MySQL service/version evidence — collected.
•	Additional open services retained in an untested-services table — included.
•	Wireshark status explicitly documented as deferred — included.
•	Assumptions/limitations explicitly documented — included.
 
Appendix A — Complete Kali Linux Process Log and Interaction Record
This appendix is intentionally more process-oriented than the main findings sections. It records the sequence followed during the Kali Linux assessment, the user's observed outputs, the interpretation given at each stage, the reason for moving to the next step, and the limits of what each result proves. It is included so the report can be used both as a technical submission and as a learning/procedure record.
A.1 Scope and Working Assumptions Established During the Process
•	The testing target used during the Kali phase was Metasploitable2 at 192.168.1.4 in the user's authorized lab.
•	Kali Linux was used as the security-analysis/scanning machine.
•	The testing was treated as an isolated/authorized lab exercise; no random Internet targets were used.
•	The project goal was open-port exposure analysis rather than exploitation or credential attacks.
•	Evidence was preferred over assumptions: a port being open was not automatically treated as a vulnerability.
•	A detected software version was not automatically treated as proof of exploitability.
•	Where a configuration issue could be established without modifying the target, non-destructive enumeration was preferred.
•	Wireshark was considered, but the user chose to defer it because capture/analysis was slow; therefore no Wireshark finding was claimed.
•	The user preferred a step-by-step workflow: perform one useful check, inspect the output, explain it, then proceed to the next service.
A.2 Initial Baseline and Service Inventory
The first major evidence collection step was the Nmap service/version scan:
User action: nmap -sV 192.168.1.4
The scan reported the host as up, 977 closed TCP ports, and 23 open TCP ports in the default 1000-port scan. The inventory included FTP, SSH, Telnet, SMTP, DNS, HTTP, RPC, SMB, r-services, Java RMI, NFS, a second FTP service, MySQL, PostgreSQL, VNC, X11, IRC, AJP and Tomcat.
Process decision: instead of attempting to investigate all 23 services simultaneously, the assessment proceeded service-by-service, prioritizing services with clear exposure or configuration questions.
A.3 HTTP / WhatWeb Investigation
The user asked what should be investigated and proceeded with HTTP fingerprinting.
Command: whatweb http://192.168.1.4
Observed evidence included HTTP 200, Apache 2.2.8, Ubuntu Linux, PHP 5.2.4-2ubuntu5.10, the Metasploitable2 page title, DAV/2 and WebDAV detection, and X-Powered-By PHP version disclosure.
Interpretation given during the process: HTTP was reachable and disclosed software/version information. WebDAV detection was treated as a fingerprint, not proof that arbitrary write operations were available. Likewise, old software was recorded as legacy software rather than automatically called exploitable.
Command: nmap --script http-title -p 80 192.168.1.4
Observed output: http-title: Metasploitable2 - Linux
Interpretation: Confirmed the web page title and target identity.
Command: nmap --script http-headers -p 80 192.168.1.4
Observed output: Server: Apache/2.2.8 (Ubuntu) DAV/2; X-Powered-By: PHP/5.2.4-2ubuntu5.10; Connection: close; Content-Type: text/html
Interpretation: Corroborated the WhatWeb fingerprint and showed version disclosure through HTTP headers.
Command: nmap --script http-methods -p 80 192.168.1.4
Observed output: Supported Methods: GET HEAD POST OPTIONS
Interpretation: Confirmed these methods in the NSE result. PUT/DELETE were not reported, so dangerous WebDAV write methods were not claimed.
A.4 FTP Investigation
The process then moved to FTP because the baseline scan identified vsftpd 2.3.4 on port 21.
Command: nmap --script ftp-anon,ftp-syst -p 21 192.168.1.4
The result explicitly reported: anonymous FTP login allowed (FTP code 230). The FTP system status also stated that the control and data connections were plain text and identified vsFTPd 2.3.4.
The user then performed a manual FTP validation:
Command: ftp 192.168.1.4
The user selected the username 'anonymous'; the server returned '230 Login successful'. The user then issued 'ls'. The server accepted the directory-listing request, but no filenames were returned in the captured output.
Important process clarification: the evidence supports anonymous authentication, but not a claim that files could be downloaded. The user was also shown how to exit the FTP client using 'bye'/'quit'.
A.5 SMB Investigation
The baseline showed ports 139 and 445. The next question was whether SMB was using a legacy protocol and what host/share information was exposed.
Command: nmap --script smb-os-discovery,smb-protocols -p 139,445 192.168.1.4
Observed evidence: SMBv1/NT LM 0.12; Samba 3.0.20-Debian; computer name 'metasploitable'; domain 'localdomain'; FQDN 'metasploitable.localdomain'.
Interpretation: SMBv1 is an obsolete/legacy protocol configuration and should be disabled where possible. The host/domain information is useful reconnaissance information. The Samba version alone was not treated as proof of a specific exploit.
Next command: nmap --script smb-enum-shares -p 139,445 192.168.1.4
The result reported anonymous READ/WRITE for IPC$ and the tmp disk share. The process explicitly distinguished IPC$ (a special IPC share) from tmp (a disk share), avoiding the incorrect assumption that IPC$ automatically means arbitrary filesystem read/write.
A.6 NFS Investigation — Step-by-Step Decision Chain
NFS was treated as a service that needed additional evidence because the first NFS NSE check did not return an export list.
First check: nmap --script nfs-showmount,nfs-ls -p 2049 192.168.1.4
Result: port 2049 was open, but the NSE output did not list an export. At this stage, the process explicitly did not claim that an NFS filesystem was exposed.
Next reasoning step: Because port 111/rpcbind was also open, the next useful command was rpcinfo -p 192.168.1.4.
rpcinfo showed portmapper on 111, NFS v2/v3/v4 on 2049, nlockmgr on dynamic ports, mountd on dynamic ports, and status services on dynamic ports.
Next validation: showmount -e 192.168.1.4
Observed output: 'Export list for 192.168.1.4: / *'. The process interpretation was that the root filesystem was exported and the client specification was '*'.
Final non-destructive validation: sudo mount -t nfs 192.168.1.4:/ /mnt
The mount succeeded. The subsequent 'mount | grep 192.168.1.4' output showed the root export mounted as NFS, with 'rw' and 'vers=3'. This supplied stronger evidence than the export list alone: the authorized Kali host successfully mounted the exported root filesystem with read/write access.
The process explicitly avoided creating, deleting or changing files. The correct cleanup was 'sudo umount /mnt'.
A.7 Telnet Investigation
Command: nmap --script telnet-encryption -p 23 192.168.1.4
Observed evidence: 'Telnet server does not support encryption'.
Second command: nmap -sV -p 23 192.168.1.4
Observed evidence: Linux telnetd.
Interpretation: this establishes an unencrypted legacy remote-administration service. The process did not perform password guessing or brute-force testing. The recommended remediation was to disable Telnet and use SSH.
A.8 SSH Investigation
Command: nmap --script ssh2-enum-algos -p 22 192.168.1.4
The output showed SHA-1-based Diffie-Hellman key-exchange variants, ssh-rsa and ssh-dss host-key algorithms, CBC/RC4/3DES-family ciphers, and MD5/SHA-1-based MACs.
Version command: nmap -sV -p 22 192.168.1.4
Observed evidence: OpenSSH 4.7p1 Debian 8ubuntu1, protocol 2.0.
Interpretation: the process classified this as a legacy cryptographic configuration rather than declaring SSH itself vulnerable. Recommended action was to upgrade and remove obsolete algorithms.
A.9 DNS Investigation
First command: nmap --script dns-recursion,dns-nsid -p 53 192.168.1.4
Observed evidence: BIND version 9.4.2 was disclosed.
The NSE output did not itself report recursion, so the process did not assume recursion was enabled.
Controlled follow-up: dig @192.168.1.4 google.com
The response returned status NOERROR, an A record for google.com, and flags 'qr rd ra'. The process explained that 'rd' means recursion desired and 'ra' means recursion available. Therefore recursion was confirmed as available to the authorized Kali client. The process explicitly did not claim Internet-wide open-resolver exposure.
A.10 MySQL Investigation
Command: nmap --script mysql-info -p 3306 192.168.1.4
Observed evidence: MySQL protocol 10, version 5.0.51a-3ubuntu5, capability flags, and SSL-related capability 'SwitchToSSLAfterHandshake'.
Interpretation: the MySQL service is network exposed and reveals a legacy version. The presence of an SSL-related capability was not interpreted as proof that every connection requires encryption. No authentication brute force was performed.
A.11 User Questions and Key Clarifications Recorded During the Process
Question: Why analyze services one by one?
Answer/clarification: Because the project is an open-port exposure assessment. A baseline scan identifies the attack surface; targeted checks then determine what each exposed service actually reveals or permits.
Question: Does an old service version automatically mean it is vulnerable?
Answer/clarification: No. Version detection establishes software/version information. A specific vulnerability claim requires separate evidence, such as an authoritative advisory or controlled validation.
Question: Does WebDAV detection prove dangerous write access?
Answer/clarification: No. WebDAV fingerprinting alone does not prove PUT/DELETE or arbitrary write capability. The HTTP method enumeration reported GET, HEAD, POST and OPTIONS.
Question: Does anonymous FTP login prove files can be downloaded?
Answer/clarification: No. It proves anonymous authentication succeeded. The observed directory listing returned no filenames, so download access was not claimed.
Question: Does NFS '/ *' prove complete filesystem compromise?
Answer/clarification: It proves the root filesystem was exported to the '*' client specification. The subsequent successful rw NFSv3 mount provided stronger evidence of accessible read/write mounting, but no destructive file operation was performed.
Question: Does DNS recursion evidence prove an Internet-wide open resolver?
Answer/clarification: No. The controlled dig test proves recursion was available to the authorized Kali client. Public Internet exposure was not inferred.
Question: Does SMB IPC$ READ/WRITE mean arbitrary filesystem write access?
Answer/clarification: Not necessarily. IPC$ is a special IPC share. The tmp disk share's reported anonymous READ/WRITE access is the more direct access-control finding.
Question: Was Wireshark included as evidence?
Answer/clarification: No. Wireshark was deferred because it was slow. The report explicitly avoids claiming packet-level findings that were not collected.
Question: Were brute-force or exploitation techniques used?
Answer/clarification: No. The documented process used service discovery, safe NSE enumeration, manual anonymous FTP login, DNS query testing, and non-destructive NFS mount validation.
A.12 Exact Process Flow Followed
1. Identify authorized target: Metasploitable2 at 192.168.1.4.
2. Run baseline Nmap service/version scan.
3. Select HTTP and fingerprint it with WhatWeb.
4. Corroborate HTTP with http-title, http-headers and http-methods.
5. Analyze FTP with ftp-anon/ftp-syst and manually confirm anonymous login.
6. Analyze SMB with smb-os-discovery/smb-protocols.
7. Enumerate SMB shares and document anonymous access reported by Nmap.
8. Check NFS; when the first NSE output did not show exports, pivot to rpcinfo.
9. Use showmount to identify the actual NFS export.
10. Perform a controlled NFS mount to validate access, then plan clean unmounting.
11. Analyze Telnet encryption support and service identity.
12. Analyze SSH algorithms and service version.
13. Analyze DNS version disclosure; use dig to verify recursion availability.
14. Analyze MySQL protocol/service information.
15. Keep remaining baseline services in a separate 'identified but not yet deeply analyzed' list.
16. Prepare findings with explicit evidence, limitations and remediation.
17. Use the same checks later for before/after hardening validation.
A.13 Important Boundary of This Appendix
This appendix records the substantive Kali Linux workflow and the questions/clarifications that were available from the conversation context used to prepare this report. It intentionally does not reproduce hidden model reasoning or private chain-of-thought. It does, however, preserve the observable commands, outputs, decisions, evidence, interpretations, limitations and user-facing explanations relevant to the project.
 
25. External Attack-Surface Assessment — Shodan / Censys Methodology
Purpose. This phase addresses the project requirement to consider how an externally positioned analyst could discover Internet-facing services using large-scale Internet search and asset-discovery platforms such as Shodan and Censys.
Important Security Boundary: Metasploitable2 at 192.168.1.4 was kept inside the authorized private laboratory and was not exposed to the public Internet. The private address 192.168.1.4 is not an Internet-routable public asset that can be meaningfully assessed through public Internet indexes.
What was completed: The external-assessment concept, comparison methodology, limitations, and report-ready procedure were documented.
What was not claimed: No Shodan/Censys result was attributed to the Metasploitable2 host because no public asset belonging to the assessment was provided or exposed.
25.1 Internal vs External Viewpoint
Viewpoint	Tool / Method	Target	What it shows	Status
Internal authorized assessment	Nmap + NSE + protocol checks	192.168.1.4	Open ports, services, versions, configurations and controlled access evidence	Completed
External attack-surface assessment	Shodan / Censys	Authorized public IP/domain only	Internet-observed ports, banners, certificates and exposed services	Method documented; direct target check pending
Packet-level correlation	Wireshark	Authorized lab traffic	Packets, protocols, flags and request/response behavior	Deferred because capture was slow

25.2 Report-Ready External Assessment Procedure
13.	Identify a public IP address or domain that is owned by the project owner or explicitly authorized for assessment.
14.	Search the authorized asset in Shodan and/or Censys without exposing the Metasploitable2 VM.
15.	Record the observation date, public IP/domain, detected ports, identified services, banners, software versions and certificate information where available.
16.	Compare the external observations with an authorized Nmap scan of the same public asset, if such scanning is permitted.
17.	Explain differences: Internet indexes may contain historical observations, may not see filtered services, and may identify services differently from an active Nmap probe.
18.	Capture screenshots or export evidence for the final report, keeping the target authorization and scope documented.
Evidence Rule: An Internet search result is evidence that a service was observed by that platform at a particular time; it is not automatically proof that the service is currently reachable or vulnerable.
26. Remaining Project Process — What Was Left After the Kali Analysis
The Kali assessment completed the core reconnaissance and service-enumeration portion. The following items were the remaining project requirements. They are included here so the final report clearly distinguishes completed work from work that still requires execution on the lab.
Project requirement	Current status	Evidence / next action
Identify open ports	COMPLETED	Nmap -sV baseline identified 23 open TCP ports in the default 1000-port scan.
Identify services and versions	COMPLETED	Nmap -sV plus targeted banner/service checks.
Analyze exposed services	SUBSTANTIALLY COMPLETED	HTTP, FTP, SMB, NFS/RPC, Telnet, SSH, DNS and MySQL received targeted analysis; remaining services are documented separately.
Identify weak / unnecessary configurations	COMPLETED FOR TESTED SERVICES	Anonymous FTP, SMBv1/anonymous share access, broad NFS root export, Telnet without encryption, legacy SSH algorithms, DNS recursion and legacy service exposure were documented.
Wireshark correlation	DEFERRED	Capture was slow; no packet-level finding is claimed.
Shodan / Censys external assessment	PENDING DIRECT EXECUTION	Requires an owned/authorized public IP or domain; Metasploitable2 remains private.
Hardening / port closure	PENDING EXECUTION	Apply changes to the authorized lab target and record exact commands/configuration changes.
Before/after validation	PENDING EXECUTION	Repeat baseline and targeted checks after hardening.
Final comparison and conclusion	READY AFTER HARDENING	Use before/after evidence to show whether exposure was reduced.

27. Hardening and Remediation Phase — Planned Execution
The purpose of this phase is not simply to list recommendations. The project should demonstrate that selected security controls were applied and then verified with the same measurement method. Because Metasploitable2 is intentionally vulnerable and may contain deliberately insecure services, changes should be made carefully and only within the isolated lab.
Area	Observed evidence	Hardening action	Verification command / check	Expected evidence
NFS	Root '/' exported to '*' and successfully mounted read/write using NFSv3.	Remove the root export; export only required directories; restrict clients and permissions.	showmount -e 192.168.1.4; nmap -p 111,2049 192.168.1.4	Root '/' no longer broadly exported; unnecessary NFS exposure reduced.
SMB	SMBv1 enabled; Nmap reported anonymous READ/WRITE for tmp share.	Disable SMBv1; remove guest/anonymous write access; restrict 139/445.	nmap --script smb-protocols,smb-enum-shares -p 139,445 192.168.1.4	SMBv1 absent and anonymous write access removed.
Telnet	Port 23 open; encryption unsupported.	Disable Telnet and use SSH for administration.	nmap -p 23 192.168.1.4	Port 23 closed.
FTP	Anonymous login succeeded on port 21.	Disable anonymous FTP unless explicitly required; restrict FTP; prefer SFTP/FTPS.	nmap --script ftp-anon -p 21 192.168.1.4	Anonymous login no longer allowed, or service closed.
SSH	Legacy DH/SHA-1, ssh-dss, CBC/RC4/3DES and older MACs advertised.	Upgrade OpenSSH/OS and remove obsolete algorithms using a modern crypto policy.	nmap --script ssh2-enum-algos -p 22 192.168.1.4	Legacy algorithms no longer advertised.
DNS	BIND 9.4.2 disclosed; recursion available to authorized Kali client.	Restrict recursion to trusted clients; minimize disclosure; upgrade BIND.	dig @192.168.1.4 google.com; nmap --script dns-nsid -p 53 192.168.1.4	Recursion restricted as intended; unnecessary version disclosure reduced.
HTTP	Apache/PHP versions disclosed; DAV/2/WebDAV detected.	Upgrade web stack; review WebDAV; remove unnecessary methods and version disclosure.	whatweb http://192.168.1.4; nmap --script http-headers,http-methods -p 80 192.168.1.4	Reduced information disclosure and unnecessary functionality.
MySQL	MySQL 5.0.51a-3ubuntu5 exposed on 3306.	Restrict database access to authorized application/management hosts; upgrade database.	nmap -p 3306 192.168.1.4; firewall validation	Port inaccessible from unauthorized network segment or service removed.
Other legacy services	rlogin, RMI, VNC, X11, IRC, AJP, Tomcat and additional services exposed.	Disable services that are not required; otherwise restrict them to trusted hosts and update where possible.	Repeat nmap -sV and targeted checks.	Only required services remain reachable.

28. Before-and-After Validation Evidence
This section is the final measurement framework. The 'Before' column is populated from the evidence already collected. The 'After' column is intentionally left as a validation field rather than inventing results that have not yet been observed.
Control / metric	Before hardening — observed	After hardening — to be measured	Pass condition
Open TCP ports	23 open TCP ports in the default 1000-port Nmap scan.	Repeat: nmap -sV 192.168.1.4	Unnecessary ports are no longer reachable.
FTP anonymous login	Anonymous login returned FTP code 230.	Repeat ftp-anon or manual authorized check.	Anonymous authentication disabled unless intentionally required.
SMBv1	NT LM 0.12 (SMBv1) reported.	Repeat smb-protocols.	SMBv1 is no longer offered.
SMB anonymous write	tmp share reported anonymous READ/WRITE.	Repeat smb-enum-shares.	Anonymous write access removed.
NFS root export	showmount reported '/ *'; authorized mount succeeded as rw, NFSv3.	Repeat showmount and NFS checks.	Root export removed or restricted to explicitly authorized hosts and required permissions.
Telnet	23/tcp open; no encryption.	Repeat Nmap port check.	Port 23 closed.
SSH algorithms	Multiple legacy algorithms advertised.	Repeat ssh2-enum-algos.	Obsolete algorithms removed.
DNS recursion	Recursion available to authorized Kali client.	Repeat controlled dig test from permitted and non-permitted network contexts where authorized.	Recursion limited to intended clients.
HTTP information disclosure	Apache/PHP/DAV information disclosed.	Repeat WhatWeb and HTTP NSE.	Unnecessary version/functionality disclosure reduced.
Database exposure	MySQL 3306 and PostgreSQL 5432 open.	Repeat port scan and firewall checks.	Database ports are restricted to intended clients.

29. Evidence Register — Final Report Table
Finding	Port(s)	Evidence collected	Security significance	Status
Anonymous FTP authentication	21/tcp	ftp-anon reported anonymous login; manual login returned 230.	Unauthenticated access to the FTP service; plaintext protocol.	Confirmed
SMBv1 and anonymous share access	139/445	smb-protocols reported SMBv1; smb-enum-shares reported anonymous READ/WRITE on tmp.	Legacy protocol and weak access control increase attack surface.	Confirmed
Broad NFS root export	111/2049 + RPC	showmount: '/ *'; mount succeeded with rw, NFSv3.	Excessive filesystem exposure and weak client restriction.	Confirmed
Unencrypted Telnet	23/tcp	telnet-encryption reported no encryption support.	Credentials/session data can be exposed to network interception.	Confirmed
Legacy SSH cryptography	22/tcp	ssh2-enum-algos reported legacy DH/SHA-1, ssh-dss, CBC/RC4/3DES and older MACs.	Weak/obsolete cryptographic options increase compatibility and downgrade risk.	Confirmed configuration finding
DNS recursion available	53/tcp/udp	dig response included ra and returned an external DNS answer.	Recursive service should be restricted to intended clients.	Confirmed for authorized Kali client; Internet-wide exposure not established
Legacy web stack / disclosure	80/tcp	WhatWeb and HTTP NSE identified Apache 2.2.8, PHP 5.2.4, DAV/2 and headers.	Legacy software and information disclosure increase attack surface.	Confirmed version/configuration exposure
Legacy MySQL	3306/tcp	mysql-info identified MySQL 5.0.51a-3ubuntu5.	Database service should not be broadly reachable; software is legacy.	Confirmed exposure
Root bind shell	1524/tcp	Nmap identified 'Metasploitable root shell'.	Direct remote administrative shell exposure.	Confirmed service identification; no connection/exploitation performed

30. Complete 23-Port Baseline Inventory
The baseline inventory below is retained as the master evidence table. It prevents the report from focusing only on the most interesting findings and demonstrates that the complete default Nmap TCP service inventory was reviewed.
Port	Service	Detected version / identity	Assessment status
21/tcp	FTP	vsftpd 2.3.4	Deeply analyzed — anonymous login confirmed
22/tcp	SSH	OpenSSH 4.7p1 Debian 8ubuntu1	Deeply analyzed — legacy algorithms confirmed
23/tcp	Telnet	Linux telnetd	Deeply analyzed — no encryption confirmed
25/tcp	SMTP	Postfix smtpd	Identified; SMTP commands enumerated
53/tcp	DNS	ISC BIND 9.4.2	Deeply analyzed — recursion available to Kali
80/tcp	HTTP	Apache 2.2.8 (Ubuntu), DAV/2	Deeply analyzed — WhatWeb + HTTP NSE
111/tcp	rpcbind	RPC #100000	Analyzed as part of NFS/RPC
139/tcp	NetBIOS/SMB	Samba 3.X–4.X	Deeply analyzed
445/tcp	SMB	Samba 3.X–4.X	Deeply analyzed
512/tcp	exec?	Service not confirmed	Open but unidentified; no vulnerability claim
513/tcp	login	OpenBSD/Solaris rlogind	Identified; legacy remote login service
514/tcp	tcpwrapped	Service not confirmed	Open; exact service not established
1099/tcp	Java RMI	GNU Classpath grmiregistry	Identified; restrict if unnecessary
1524/tcp	bindshell	Metasploitable root shell	Confirmed service exposure; no exploitation
2049/tcp	NFS	NFS v2–v4	Deeply analyzed — root export and rw mount confirmed
2121/tcp	FTP	ProFTPD 1.3.1	Identified; legacy FTP service
3306/tcp	MySQL	5.0.51a-3ubuntu5	Deeply analyzed — protocol info/version
5432/tcp	PostgreSQL	8.3.0–8.3.7	Identified; brute-force script timed out; no auth result
5900/tcp	VNC	RFB 003.003	Identified; no authentication testing
6000/tcp	X11	X11; access denied	Identified; access denied during probe
6667/tcp	IRC	UnrealIRCd	Identified; banner disclosed hostname
8009/tcp	AJP13	Apache Jserv Protocol v1.3	Identified; restrict to trusted app/web hosts
8180/tcp	HTTP/Tomcat	Apache Tomcat 5.5 / Coyote	Identified; legacy app server exposure

31. Final Completion Status
Core technical assessment: Completed. The authorized Kali-to-Metasploitable2 reconnaissance, service identification, targeted enumeration, evidence collection and risk documentation are included.
Report documentation: Completed. The report contains the methodology, command evidence, interpretations, limitations, evidence tables, remediation plan and reproducibility appendix.
External attack-surface component: Methodology documented. Direct Shodan/Censys assessment of Metasploitable2 was intentionally not performed because the target is a private lab host and must not be exposed to the Internet.
Hardening demonstration: Not yet executed in the recorded evidence. The report includes the exact hardening objectives and the before/after validation framework so the changes can be demonstrated without inventing results.
Final before/after comparison: Pending the hardening run and post-hardening rescan. The report deliberately leaves the after-results open rather than fabricating them.
32. Final Conclusion
The project successfully demonstrated an evidence-based open-port exposure assessment against an intentionally vulnerable Metasploitable2 host in an authorized laboratory. The baseline Nmap scan identified 23 open TCP services in the default 1000-port range. Targeted enumeration then converted a simple port list into concrete configuration and exposure findings.
The strongest demonstrated findings were the broad NFS root export with successful read/write mounting, SMBv1 together with reported anonymous read/write access on the tmp share, anonymous FTP authentication, unencrypted Telnet, legacy SSH cryptographic algorithms, DNS recursion available to the authorized client, and exposure of multiple legacy web/database services. A direct root bind shell was also identified on port 1524 as part of the Metasploitable2 baseline.
The assessment also demonstrates an important professional security-analysis principle: evidence must be separated from assumption. An old software version is documented as a legacy/version finding unless a separate authoritative vulnerability analysis establishes exploitability. Similarly, an observed service does not automatically mean that every possible attack against it succeeds.
The remaining project work is therefore measurement-oriented: apply selected hardening controls, repeat the same scans, record the post-hardening evidence, and compare the before/after attack surface. The external attack-surface section should be executed only against an owned or explicitly authorized public asset; the Metasploitable2 VM should remain isolated.

#ope
