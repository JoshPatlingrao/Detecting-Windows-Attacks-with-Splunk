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
  - 
