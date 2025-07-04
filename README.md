# Detecting-Windows-Attacks-with-Splunk

## Detecting Common User/Domain Recon
### Notes
Domain Recon
- AD domain recon is crucial in a cryberattack lifecycle
  - Attackers want as much info as possible: architecture, network topology, security measures, and potential vulnerabilities.
    - Focus on: domain controllers, user accounts, groups, trust relationships, organizational units (OUs), group policies, and other vital objects.
- With enough info, attackers can pinpoint high-value targets, escalate privileges, and move laterally within the network

User/Domain Recon Using Native Windows Executables
- Attacker executes the net group command to obtain a list of Domain Admins
  - net group "Domain Admins" /domain
    - If succesful, will display accounts with admin privileges
- Other tools used:
  - whoami /all
    - Displays current user and all security info about the user, including: group memberships, privileges, authentication ID, SID
  - wmic computersystem get domain
    - Uses WMIC (Windows Management Instrumentation Command-line) to display the domain to which the current computer is joined
    - Helps attackers to pivot from a non-domain-joined to a domain-joined environment.
  - net user /domain
    - Lists all domain user accounts by querying the domain controller
    - Used to identify potential targets
  - arp -a
    - Displays the ARP cache, which maps IP addresses to MAC addresses
    - Identifies other active devices on the local subnet
  - nltest /domain_trusts
    - Lists domain trust relationships
    - Useful for mapping multi-domain or multi-forest environments. Shows possible lateral movement paths across domain boundaries

User/Domain Recon Using BloodHound/SharpHound
- BloodHound: open-source domain recon tool created to analyze and visualize the AD environment
  - Used to find attack paths and potential security risks within an organization's AD infrastructure
  - Leverages graph theory and relationship mapping to know trust relationships, permissions, and group memberships within the AD domain
- Sharphound: a C# data collector for BloodHound
  - Runs: .\Sharphound3.exe -c all
    - To collect all sorts of data

BloodHound Detection Opportunities
- BloodHound collector executes numerous LDAP queries directed at the Domain Controller to learn more about the domain
  - Hard to monitor LDAP queries. Windows Event log doesn't record them by default.
    - Best bet is to check for Event 1644 - LDAP performance monitoring log, but some events may not be recorded
  - Better to use: Windows ETW provider Microsoft-Windows-LDAP-Client
    - SilkETW & SilkService: versatile C# wrappers for ETW, simplifies intricacies of ETW, provides accessible interface for research and introspection
- List of LDAP filters used for recon tools: https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/hunting-for-reconnaissance-activities-using-ldap-search-filters/ba-p/824726

Detecting User/Domain Recon With Splunk
- index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 earliest=1690447949 latest=1690450687 | search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*)) | stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user | where mvcount(process) > 3
- Breakdown:
  - Index & Source Filter:
    - Targets events in the main index.
    - Source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational (Sysmon logs in XML format).
  - Event ID Filter:
    - Filters for Event ID 1, which corresponds to process creation events in Sysmon.
  - Time Range Filter:
    - Only includes events between Unix timestamps 1690447949 and 1690450687.
  - Process Name Filter:
    - Focuses on specific system/network tools (e.g., arp.exe, ipconfig.exe).
    - Includes events where:
      - process_name is cmd.exe or powershell.exe
      - And process field contains specific substrings (indicating commands run inside a shell).
  - Statistical Aggregation:
    - Groups events by parent_process, parent_process_id, dest, and user.
    - Collects:
      - values(process) → list of unique processes.
      - min(_time) → timestamp of the first event in each group.
  - Result Filtering:
    - Keeps only results where the number of processes (count(process)) is greater than 3.
    - Highlights suspicious parent processes spawning multiple child processes.

Detecting Recon By Targeting BloodHound
- index=main earliest=1690195896 latest=1690285475 source="WinEventLog:SilkService-Log" | spath input=Message | rename XmlEventData.* as * | table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter | sort 0 _time | search SearchFilter="*(samAccountType=805306368)*" | stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId | where count > 10 | convert ctime(maxTime)
- Breakdown
  - Filtering by Index and Source:
    - Searches the main index.
    - Filters for logs with source: WinEventLog:SilkService-Log (from SilkETW).
  - Time Range Filter:
    - Filters events between Unix timestamps 1690195896 and 1690285475.
  - Path Extraction:
    - Uses spath to extract fields from the Message field (likely structured as JSON or XML).
  - Field Renaming:
    - Uses rename to strip XmlEventData. prefix from field names for simplicity.
  - Tabulating Results:
    - Uses table to display selected columns: _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
  - Sorting:
    - Uses sort 0 _time to sort all results by _time (ascending).
    - 0 means no limit on the number of results sorted.
  - Search Filter:
    - Filters events where SearchFilter contains: *(samAccountType=805306368)*
      - (likely targeting LDAP queries for user accounts).
  - Statistics:
    - Groups events by: ComputerName, ProcessName, ProcessId
    - Each group, calculates:
      - min(_time) as _time → First occurrence.
      - max(_time) as maxTime → Last occurrence.
      - count → Number of events in the group.
      - values(SearchFilter) → Unique search filters used.
  - Filtering by Event Count:
    - Uses where to filter groups with count > 10.
    - Focuses on processes that ran >10 LDAP searches with the target filter.
  - Time Conversion
    - Uses convert to change maxTime from Unix timestamp to human-readable ctime format.
### Walkthrough
Q1. Modify and employ the Splunk search provided at the end of this section on all ingested data (All time) to find all process names that made LDAP queries where the filter includes the string *(samAccountType=805306368)*. Enter the missing process name from the following list as your answer. N/A, Rubeus, SharpHound, mmc, powershell, _
- Open Splunk in Firefox and go to 'Search' tab
- Run the Splunk query in the (Detecting Recon By Targeting BloodHound) section and set time range to 'All Time'
- Modify the query
  - Remove the time range: earliest=1690195896 latest=1690285475
    - This is to go through all LDAP query events, not just in a specific time range
  - Change the count from 'where count > 10' to 'where count > 1'
    - This ensures that it will list all processes that made LDAP queries at least once.
- Answer is: rundll32

## Password Spraying
### Notes
Password Spraying
- Spreads out the attack across multiple accounts using a limited set of commonly used or easily guessable passwords
  - Want to evade account lockout policies
    - Applied to defend against brute-force attacks on individual accounts
- Lowers the chance of triggering account lockouts
  - Each user account receives only a few password attempts
  - Attack is less noticeable.

Password Spraying Detection Opportunities
- Done in Windows
- Look for multiple failed logons: Event ID 4625 - Failed Logon
  - From multiple accounts but comes from same source IP.
  - Within short time frame
- Other useful event logs:
  - 4768 and ErrorCode 0x6 - Kerberos Invalid Users
  - 4768 and ErrorCode 0x12 - Kerberos Disabled Users
  - 4776 and ErrorCode 0xC000006A - NTLM Invalid Users
  - 4776 and ErrorCode 0xC0000064 - NTLM Wrong Password
  - 4648 - Authenticate Using Explicit Credentials
  - 4771 - Kerberos Pre-Authentication Failed

Detecting Password Spraying With Splunk
- index=main earliest=1690280680 latest=1690289489 source="WinEventLog:Security" EventCode=4625 | bin span=15m _time | stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason
- Breakdown
  - Filtering by Index, Source, and EventCode:
    - Filters events from index=main
    - Source is WinEventLog:Security
    - EventCode is 4625 (represents failed Windows logon attempts)
  - Time Range Filter:
    - Limits events to those between Unix timestamps 1690280680 and 1690289489
  - Time Binning:
    - Uses the bin command to group events into 15-minute intervals (_time)
    - Helps identify trends or patterns over time
  - Statistical Aggregation (stats command):
    - Groups events by: src (source host), Source_Network_Address, dest (destination), EventCode, Failure_Reason
    - Calculates:
      - values(user) as Users: Lists all unique users involved in each group
      - dc(user) as dc_user: Counts the number of distinct users per group

### Walkthrough
Q1. Employ the Splunk search provided at the end of this section on all ingested data (All time) and enter the targeted user on SQLSERVER.corp.local as your answer.
- Open Firefox, go to Splunk, go to 'Search' tab and run the Splunk query
  - http://IPADDRESS:8000
- Modify the query:
  - Remove the time range: earliest=1690280680 latest=1690289489
    - It will remove the time range and query for all failed login events
  - Add the destination to the specified domain after the EventCode
    - dest="SQLSERVER.corp.local"
- Answer is: sa

## Detecting Responder-Like Attacks
### Notes
LLMNR/NBT-NS/mDNS Poisoning
- Vocab
  - LLMNR (Link-Local Multicast Name Resolution)
  - NBT-NS (NetBIOS Name Service)
- Network-level attacks that exploit inefficiencies in these name resolution protocols.
- LLMNR and NBT-NS are used to resolve hostnames to IP addresses on local networks when the fully qualified domain name (FQDN) resolution fails
  - No built-in security features. Very susceptible to spoofing and poisoning attacks
    - Attackers use Responder tool to execute the attack
      - https://github.com/lgandx/Responder

Attack Steps
- Victim device sends a name resolution query for a mistyped hostname
- DNS fails to resolve the mistyped hostname
- Victim device sends a name resolution query for the mistyped hostname using LLMNR/NBT-NS
- Attacker's host responds to the query and pretends to know the identity of the requested host
  - LLMNR (UDP 5355)
  - NBT-NS (UDP 137)
- Victim device is redirected to adversary-controlled system

Responder Detection Opportunities
- Detection is diffult for this attack
- Deploy network monitoring solutions to detect unusual LLMNR and NBT-NS traffic patterns, such as an elevated volume of name resolution requests from a single source.
- Employ a honeypot approach - name resolution for non-existent hosts should fail. If an attacker is present and spoofing LLMNR/NBT-NS/mDNS responses, name resolution will succeed.
  - https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/

Detecting Responder-like Attacks With Splunk
- Options:
  - index=main earliest=1690290078 latest=1690291207 SourceName=LLMNRDetection | table _time, ComputerName, SourceName, Message
    - This one focuses on the LLMNRDetection as an event provider
  - index=main earliest=1690290078 latest=1690291207 EventCode=22 | table _time, Computer, user, Image, QueryName, QueryResults
    - Can use Sysmon Event ID 22 to track DNS queries on non-existent/mistyped file shares
  - index=main earliest=1690290814 latest=1690291207 EventCode IN (4648) | table _time, EventCode, source, name, user, Target_Server_Name, Message | sort 0 _time
    - Can also use Event 4648, used to detect explicit logons to rogue file shares which attackers might use to gather legitimate user credentials

### Walkthrough
Q1. Modify and employ the provided Sysmon Event 22-based Splunk search on all ingested data (All time) to identify all share names whose location was spoofed by 10.10.0.221. Enter the missing share name from the following list as your answer. myshare, myfileshar3, _
- Open Firefox, go to Splunk, go to 'Search' tab and run the Splunk query
  - http://IPADDRESS:8000
- Run the EventCode=22 version of the query
- Scroll and observe the myshare and myfileshar3 events
  - Both share the QueryResults having the value '::1;::ffff:10.10.0.221;' which is the attacker machine spoofing these share names
- Modify the query:
  - Remove the time range: earliest=1690280680 latest=1690289489
    - It will remove the time range and query for all failed login events
  - Add the QueryResults that indicate the spoofing
    - QueryResults="::1;::ffff:10.10.0.221;"
- Run the query and it will show the 3 share names that have been spoofed by 10.10.0.221
- Answer is: f1nancefileshare

## Detecting Kerberoasting/AS-REProasting
### Notes
Kerberoasting
- A technique targeting service accounts in AD environments to extract and crack their password hashes
- It exploits Kerberos service tickets encryption and usage of weak or easily crackable passwords for service accounts

Attack Steps
- Identify Target Service Accounts:
  - Attacker searches for service accounts in AD
  - Enumerates accounts with Service Principal Names (SPNs) set
  - Why:
    - SPNs are linked to services like SQL Server, Exchange, or custom apps.
    - Service accounts often have elevated privileges.
  - Attackers may use tools like Rubeus to automate SPN enumeration
- Request TGS Ticket:
  - Attacker requests TGS (Ticket Granting Service) tickets for service accounts, from Key Distribution Center (KDC).
  - TGS tickets contain encrypted password hashes of the targeted service accounts.
    - This will be brute-forced offline
  - Rubeus is used to automate the TGS ticket requests.
- Offline Brute-Force Attack:
  - Attacker runs offline brute-force techniques, using password cracking tools like Hashcat or John the Ripper, to attempt to crack the encrypted password hashes.

Benign Service Access Process & Related Events
- Rehash of Kerberos operations and tickets
- Related Events:
  - Event ID 4768 (Kerberos TGT Request):
    - Triggered when a client requests a TGT from the KDC
    - Logged on the domain controller in the Security log.
  - Event ID 4769 (Kerberos Service Ticket Request):
    - Occurs when the client uses the TGT to request a TGS ticket for a service (e.g., MSSQL server’s SPN).
    - Also logged on the domain controller.
  - Event ID 4624 (Logon):
    - Logged on the target server (e.g., MSSQL server) after the client uses the TGS to authenticate and successfully log in.
    - Indicates successful connection using the service account tied to the SPN.

Kerberoasting Detection Opportunities
- Done during recon phase for privileged service accounts, look for LDAP activity
- Legitimate vs Kerberoasting: TGS tickets are requested, but legitimate user will connect to the server and present the TGS ticket
  - Attacker takes the TGS ticket to break encryption and steal credentials.

Detecting Kerberoasting With Splunk
- Benign TGS Request
  - index=main earliest=1690388417 latest=1690388630 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc) | dedup RecordNumber | rex field=user "(?<username>[^@]+)" | table _time, ComputerName, EventCode, name, username, Account_Name, Account_Domain, src_ip, service_name, Ticket_Options, Ticket_Encryption_Type, Target_Server_Name, Additional_Information
  - Breakdown
    - index=main earliest=1690388417 latest=1690388630
      - Limits the search to the main index.
      - Filters events that occurred between the given epoch timestamps (specific time range).
    - EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
      - Includes events with: EventCode=4648, or EventCode=4769 only if the service_name is iis_svc.
    - | dedup RecordNumber
      - Removes duplicate events using the RecordNumber field to ensure unique records.
    - | rex field=user "(?<username>[^@]+)"
      - Uses regular expression to extract the username from the user field (removes domain part after @).
      - Stores the result in a new field called username.
    - | table _time, ComputerName, EventCode, name, username, Account_Name, Account_Domain, src_ip, service_name, Ticket_Options, Ticket_Encryption_Type, Target_Server_Name, Additional_Information
      - Formats the output as a table displaying only the listed fields for readability and analysis.
- Detecting Kerberoasting - SPN Querying
  - index=main earliest=1690448444 latest=1690454437 source="WinEventLog:SilkService-Log" | spath input=Message | rename XmlEventData.* as * | table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter | search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
- Detecting Kerberoasting - TGS Requests
  - index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc) | dedup RecordNumber | rex field=user "(?<username>[^@]+)" | bin span=2m _time | search username!=*$ | stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username | where !match(Events,"4648")
- Detecting Kerberoasting Using Transactions - TGS Requests
  - index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc) | dedup RecordNumber | rex field=user "(?<username>[^@]+)" | search username!=*$ | transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769) | where closed_txn=0 AND EventCode = 4769 | table _time, EventCode, service_name, username

AS-REPRoasting
- A technique used in Active Directory environments to target user accounts without pre-authentication enabled
- Pre-Auth in Kerberos is a security feature, users must prove their identity before TGT is issued

Attack Steps:
- Identify Target User Accounts: Attacker identifies user accounts without pre-authentication enabled.
- Request AS-REQ Service Tickets: The attacker initiates an AS-REQ service ticket request for each identified target user account.
- Offline Brute-Force Attack: The attacker captures the encrypted TGTs and employs offline brute-force techniques to attempt to crack the password hashes.

Kerberos Pre-Auth
- When a user tries to access a network resource or service, the client sends an authentication request AS-REQ to the KDC
- If pre-auth is enabled, this request also contains an encrypted timestamp (pA-ENC-TIMESTAMP)
  - KDC attempts to decrypt this timestamp using the user password hash and, if successful, issues a TGT to the user.
- If pre-auth is disabled, there is no timestamp validation by the KDC, allowing users to request a TGT ticket without knowing the user password.

AS-REPRoasting Detection Opportunities
- Monitor LDAP activity during reocn phase for service accounts
- Kerberos authentication Event ID 4768 (TGT Request) contains a PreAuthType attribute in the additional information part of the event indicating whether pre-authentication is enabled for an account

Detecting AS-REPRoasting With Splunk
- Detecting AS-REPRoasting - Querying Accounts With Pre-Auth Disabled
  - index=main earliest=1690392745 latest=1690393283 source="WinEventLog:SilkService-Log" | spath input=Message | rename XmlEventData.* as * | table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter | search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
- Detecting AS-REPRoasting - TGT Requests For Accounts With Pre-Auth Disabled
  - index=main earliest=1690392745 latest=1690393283 source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0 | rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)" | table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type

### Walkthrough
Q1. Modify and employ the Splunk search provided at the "Detecting Kerberoasting - SPN Querying" part of this section on all ingested data (All time). Enter the name of the user who initiated the process that executed an LDAP query containing the "*(&(samAccountType=805306368)(servicePrincipalName=*)*" string at 2023-07-26 16:42:44 as your answer. Answer format: CORP\_
- Open Firefox, go to Splunk, go to 'Search' tab and run the Splunk query
  - http://IPADDRESS:8000
- Run the specified query
- Modify the query:
  - Remove the time range: earliest=1690280680 latest=1690289489
    - It will remove the time range and query for all LDAP events
    - This will also show relevant events on the same time and date
  - 
- Answer is: CORP\LANDON_HINES

## Detecting Pass the Hash
### Notes
Pass-the-Hash
- A technique utilized by attackers to authenticate to a networked system using the NTLM hash of a user's password instead of the plaintext password
- Takes advantage on how Windows stores password hashes in memory.
  - If attacker has Admin privileges, they can capture the hash and reuse for lateral movement

Attack Steps
- Attacker uses tools such as Mimikatz to extract the NTLM hash of a user currently logged in the compromised system. Local admin privileges are required on the system to extract the user's hash.
- Attacker can then authenticate as the targeted user on other systems or network resources without needing to know the actual password
- Attacker can use the authenticated session, moving laterally within the network, gaining unauthorized access to other systems and resources

Windows Access Tokens & Alternate Credentials
- Access Token: a data structure that defines the security context of a process or thread
  - Contains info about the associated user account's identity and privileges
  - References a LogonSession generated at user logon
    - LogonSession contains Username, Domain, and AuthenticationID (NTHash/LMHash), which are used when a process attempts to access remote resources
- When user logs on, the system verifies the user's password by comparing it with information stored in a security database
  - Once auth is confirmed, access token is generated
  - Any process executed by this user also has a copy of the access token.
    - https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens
- Alt Credentials: provides a way to supply different login credentials for specific actions or processes without altering the user's primary login session
  - It allows a user/process to execute certain commands or access resources as a different user without logging out or switching user accounts
  - The command 'runas' allows this.
    - This also generates a new access token, verified by 'whoami' command
    - Also contains '/netonly' flag, which indicates that user information for it are remote access only
  - The 'whoami' command returns the original credentials, but the created processes through 'runas' will have privileges of the 'mask' user account

Pass-the-Hash Detection Opportunities
- 'runas' comand execution
  - When runas command is executed without the /netonly flag - Event ID 4624 (Logon) with LogonType 2 (interactive).
  - When runas command is executed with the /netonly flag - Event ID 4624 (Logon) with LogonType 9 (NewCredentials).
    - False Positives could occur
    - True Positives has Mimikatz access the LSASS process memory to change LogonSession credential materials
      - Relate the events to 'User Logon with NewCredentials' events with 'Sysmon Process Access Event Code 10'.

Detecting Pass-the-Hash With Splunk
- index=main earliest=1690450689 latest=1690451116 (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe") OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo) | sort _time, RecordNumber | transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10) | stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process | fields - count
- Breakdown:
  - index=main earliest=1690450689 latest=1690451116:
    - Limits the search to the main index.
    - Time range specified by epoch timestamps (earliest=1690450689 latest=1690451116).
  - (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe"):
    - Source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
    - TargetImage: lsass.exe (indicates process access to LSASS).
    - Excludes: Defender process (MsMpEng.exe) as a SourceImage.
  - OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo):
    - Source: WinEventLog:Security
    - Logon_Type = 9 (NewCredentials)
    - Logon_Process = seclogo (typical for remote logons via runas or remote tools).
  - | sort _time, RecordNumber:
    - Sorts by _time and RecordNumber for chronological analysis.
  - | transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10):
    - transaction command groups events on the same host within 1 minute.
    - Starts with Sysmon EventCode=10 and ends with Security EventCode=4624.
    - Links potential LSASS access to a remote logon event.
  - | stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process:
    - stats count by several fields to show event combinations and activity context.
  - | fields - count:
    - Removes the count field from the results.

### Walkthrough
Q1. A Pass-the-Hash attack took place during the following timeframe earliest=1690543380 latest=1690545180. Enter the involved ComputerName as your answer.
- Open Firefox, go to Splunk, go to 'Search' tab and run the Splunk query
  - http://IPADDRESS:8000
- Modify the time range of the query as specified by the question
- Answer is: BLUE.corp.local

## Detecting Pass-the-Ticket
### Notes
Pass-the-Ticket (PtT)
- A lateral movement technique on a network by abusing Kerberos TGT and TGS tickets
- It leverages Kerberos tickets to authenticate to other systems and access network resources without needing to know the users' passwords

Attack Steps
- Attacker gains admin access to a system, either through an initial compromise or privilege escalation
- Uses tools such as Mimikatz or Rubeus to extract valid TGT or TGS tickets from the compromised system's memory
- Submits the extracted ticket for the current logon session
- Attacker can now authenticate to other systems and network resources without needing plaintext passwords

Related Windows Security Events
- Event ID 4648 (Explicit Credential Logon Attempt): This event is logged when explicit credentials (e.g., username and password) are provided during logon.
- Event ID 4624 (Logon): This event indicates that a user has successfully logged on to the system.
- Event ID 4672 (Special Logon): This event is logged when a user's logon includes special privileges, such as running applications as an administrator.
- Event ID 4768 (Kerberos TGT Request): This event is logged when a client requests a Ticket Granting Ticket (TGT) during the Kerberos authentication process.
- Event ID 4769 (Kerberos Service Ticket Request): When a client requests a Service Ticket (TGS Ticket) to access a remote service during the Kerberos authentication process, Event ID 4769 is generated.

Pass-the-Ticket Detection Opportunities
- Difficult, attackers are leveraging valid Kerberos tickets instead of traditional credential hashes
  - The gievaway is that Kerberos Authentication process will be partial
  - Attacker imports a used TGT to a logon session and requests for a TGS, but imported TGT never had an initial request for it from the attacker, so no associated Event ID 4768
- Look for Event ID 4769 (Kerberos Service Ticket Request) or Event ID 4770 (Kerberos Service Ticket was renewed) without a prior Event ID 4768 (Kerberos TGT Request) from the same system within a specific time window.
- Look for mismatches between Service and Host IDs (in Event ID 4769) and the actual Source and Destination IPs (in Event ID 3)
  - False positives are possible, but unusual names should be investigated
- When a TGS ticket is imported, review Event ID 4771 (Kerberos Pre-Authentication Failed) for mismatches between Pre-Authentication type and Failure Code
- Apply these with behavior-based detection to minimize False Positives

Detecting Pass-the-Ticket With Splunk
- index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770) | rex field=user "(?<username>[^@]+)" | rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)" | transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768) | where closed_txn=0 | search NOT user="*$@*" | table _time, ComputerName, username, src_ip_4, service_name, category
- Breakdown
  - index=m0ain earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770):
    - Searches the main index within the specified time range.
    - Limits to events from WinEventLog:Security.
    - Filters:
      - EventCode must be one of 4768, 4769, or 4770 (Kerberos authentication-related).
      - Excludes machine accounts by filtering out users ending in $ (user!=*$).
  - | rex field=user "(?<username>[^@]+)":
    - Extracts username from the user field (everything before @).
  - | rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)":
    - Extracts IPv4 address (src_ip_4) from src_ip, even if stored in IPv6-mapped format.
  - | transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768):
    - Groups events by username and src_ip_4.
    - Each transaction starts with EventCode=4768 (Kerberos TGT request).
    - Maximum transaction span is 10 hours.
    - keepevicted=true: includes incomplete transactions.
  - | where closed_txn=0:
    - Keeps only open transactions (no ending event), possibly indicating incomplete or anomalous authentication sequences.
  - | search NOT user="*$@*":
    - Removes users matching the pattern *$@* (likely malformed or irrelevant usernames).
  - | table _time, ComputerName, username, src_ip_4, service_name, category:
    - Displays selected fields in a table: _time, ComputerName, username, src_ip_4, service_name, and category.

### Walkthrough
Q1. Execute the Splunk search provided at the end of this section to find all usernames that may be have executed a Pass-the-Ticket attack. Enter the missing username from the following list as your answer. Administrator, _
- Open Firefox, go to Splunk, go to 'Search' tab and run the Splunk query
  - http://IPADDRESS:8000
- Run the query
- Answer is: YOUNG_WILKINSON

## Detecting Overpass-the-Hash
### Notes
Detecting Overpass-the-Hash
- Allows authentication to occur via Kerberos rather than NTLM. Both NTLM hashes or AES keys can serve as a basis for requesting a Kerberos TGT

Attack Steps
- Attacker uses tools such as Mimikatz to extract the NTLM hash of a user who is currently logged in to the compromised system.
  - Must have at least local administrator privileges on the system to be able to extract the hash of the user
- Use a tool such as Rubeus to craft a raw AS-REQ request for a specified user to request a TGT ticket
  - Doesn't require elevated privileges on the host to request the TGT, stealthier than Mimikatz Pass the Hash attack
- Analogous to the Pass-the-Ticket technique, the attacker submits the requested ticket for the current logon session

Overpass-the-Hash Detection Opportunities
- For Mimikatz, it has same artifacts as Pass the Hash attack, can be detected using the same strategies.
- For Rubeus, the previous strategy only works if the requested TGT is used on another host
  - Rubeus sends an AS-REQ request directly to the Domain Controller (DC), generating Event ID 4768 (Kerberos TGT Request)
  - Communication with the DC (TCP/UDP port 88) from an unusual process can serve as an indicator of a potential Overpass-the-Hash attack

Detecting Overpass-the-Hash With Splunk (Targeting Rubeus)
- index=main earliest=1690443407 latest=1690443544 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1 | eventstats values(process) as process by process_id | where EventCode=3 | stats count by _time, Computer, dest_ip, dest_port, Image, process | fields - count

### Walkthrough
Q1. Employ the Splunk search provided at the end of this section on all ingested data (All time) to find all involved images (Image field). Enter the missing image name from the following list as your answer. Rubeus.exe, _.exe
- Open Firefox, go to Splunk, go to 'Search' tab and run the Splunk query
  - http://IPADDRESS:8000
- Modify the specified query and remove the time range to query for all events
- Answer is: rundll32.exe

## Detecting Golden Tickets/Silver Tickets
### Notes
Golden Ticket
- Attacker forges a TGT to gain unauthorized access to a Windows Active Directory domain as a domain administrator
  - TGT has arbitrary credentials, but is used to pretend as a domain admin
- Stealthy and persistent
  - Forged ticket has a long validity period

Attack Steps
- Attacker extracts the NTLM hash of the KRBTGT account using a DCSync attack (alternatively, they can use NTDS.dit and LSASS process dumps on the Domain Controller).
- With the KRBTGT hash, attacker forges a TGT for an arbitrary user account, assigning it domain administrator privileges
- Attacker injects the forged TGT in the same manner as a Pass-the-Ticket attack

Golden Ticket Detection Opportunities
- Hard to detect, TGT can be forged offline by an attacker, no trace of Mimikatz execution
- Monitor common methods of extracting the KRBTGT hash:
  - DCSync attack
  - NTDS.dit file access
  - LSASS memory read on the domain controller (Sysmon Event ID 10)

Detecting Golden Tickets With Splunk (Yet Another Ticket To Be Passed Approach)
- index=main earliest=1690451977 latest=1690452262 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770) | rex field=user "(?<username>[^@]+)" | rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)" | transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768) | where closed_txn=0 | search NOT user="*$@*" | table _time, ComputerName, username, src_ip_4, service_name, category

Silver Ticket
- Attacker has the password hash of a target service account (e.g., SharePoint, MSSQL) may forge Kerberos TGS. This is Silver Ticket
- Can impersonate any user, but only allows attacker to access a specific resource (e.g., MSSQL) and the system hosting the resource

Attack Steps
- Attacker extracts the NTLM hash of the targeted service account (or the computer account for CIFS access) using tools like Mimikatz or other credential dumping techniques
- Generate a Silver Ticket using the extracted NTLM hash
  - Use tools like Mimikatz to create a forged TGS ticket for the specified service.
- The attacker injects the forged TGT in the same manner as a Pass-the-Ticket attack.

Silver Ticket Detection Opportunities
- Hard to detect, no simple indicators of attack
  - Both Golden and Silver Ticket attacks, any user can be used, including non-existent ones
    - Event ID 4720 (A user account was created) can help identify newly created users.
- No validation for user permissions
  - Event ID 4672 (Special Logon) can be employed to detect anomalously assigned privileges

Detecting Silver Tickets With Splunk
- Detecting Silver Tickets With Splunk Through User Correlation
  - index=main latest=1690545656 EventCode=4624 | stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user | eval last24h = 1690451977 | where firstTime > last24h ```| eval last24h=relative_time(now(),"-24h@h")``` | convert ctime(firstTime) | convert ctime(last24h) | lookup users.csv user as user OUTPUT EventCode as Events | where isnull(Events)
  - Breakdown:
    - index=main latest=1690545656 EventCode=4624:
      - Searches in the main index.
      - Limits to events with EventCode=4624 (successful logons).
      - Only includes events before timestamp 1690545656.
    - | stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user:
      - Finds the earliest logon time (firstTime) per user.
      - Collects associated ComputerName and EventCode values.
    - eval last24h = 1690451977:
      - Sets a static time threshold for filtering recent logins.
    - where firstTime > last24h:
      - Keeps only users whose first login occurred after the time threshold.
      - Converts firstTime and last24h from epoch to readable timestamps.
    - eval last24h=relative_time(now(),"-24h@h"):
      - (Commented out) — would dynamically set last24h to 24 hours ago.
    - | convert ctime(firstTime):
      - Converts the firstTime field from epoch time to a human-readable format.
    - | convert ctime(last24h):
      - Converts the last24h field from epoch time to a human-readable format.
    - lookup users.csv user as user OUTPUT EventCode as Events:
      - Compares users found in the log against those listed in users.csv.
    - where isnull(Events):
      - Keeps only users not found in the lookup file — i.e., potentially new or unauthorized accounts.
- Detecting Silver Tickets With Splunk By Targeting Special Privileges Assigned To New Logon
  - index=main latest=1690545656 EventCode=4672 | stats min(_time) as firstTime, values(ComputerName) as ComputerName by Account_Name | eval last24h = 1690451977 ```| eval last24h=relative_time(now(),"-24h@h") ``` | where firstTime > last24h | table firstTime, ComputerName, Account_Name | convert ctime(firstTime)

### Walkthrough
Q1. For which "service" did the user named Barbi generate a silver ticket?
