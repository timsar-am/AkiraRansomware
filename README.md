# AkiraRansomware
# PROJECT NAME

Memory Dump Analysis- Investigating Akira Ransomware

## Objective

Today I am going to complete a lab provided by CyberDefenders. 

Scenario: As a member of the DFIR team, you're tasked with investigating a ransomware attack involving Akira ransomware that has impacted critical systems. You’ve been provided with a memory dump from one of the compromised machines. Your goal is to analyze the memory for indicators of compromise, trace the ransomware’s entry point, and identify any malicious activity to assess the incident and guide the response strategy. 

Category: Endpoint Forensics 

Tactics: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Command and Control

### Tactics

-Execution
-Persistence
-Privilege Escalation
-Credential Access
-Lateral Movement


### Tools Used

Volatility 3, Timeline Explorer, EvtxECmd, Powershell, Bstrings

## Steps

Question: While analyzing the memory dump, identifying the compromised machine's network domain affiliation is a crucial step in understanding the attack's scope. What is the domain to which the infected machine is joined?

Info like this is stored in the registry. A quick search lead me to domain info being in the following registry key: System\ControlSet001\Services\Tcpip\Parameters

I am going to move the memory dump file into the Volatility 3 folder to make it easy. 

python vol.py -f "memory.dmp  windows.registry.printkey --key "ControlSet001\Services\Tcpip\Parameters"

Here we get the answer. Cydef.enterprise

![image](https://github.com/user-attachments/assets/2fdaa8cc-ed04-4898-9cfe-f37d955cddd8)

Question: Identifying the shared file path accessed by the attacker is crucial for understanding the scope of the breach and determining which files may have been compromised. What is the local path of the file that was shared on the file server? 

This is also in the windows registry. I think most of the info we need will be in the ControlSet001 subkey.

python vol.py -f  memory.dmp windows.registry.printkey –key "ControlSet001\Services\LanmanServer\Shares"

Here we find the answer. Z:\Shares\data

![image](https://github.com/user-attachments/assets/82cd440e-586d-4992-a0c0-156a7a834529)

Question: Identifying the source of failed RDP connection attempts is crucial for tracing the compromised machine and analyzing the attacker's behavior. What is the IP address of the machine that attempted to connect to the file serve?

We know that failed logon attempts go under Event ID 4625. 

I’m gonna have to dump the memory file. I create a folder on my desktop.

python vol.py -f memory.dmp -o "C:\Users\Administrator\Desktop\dump" windows.dumpfiles

After 15 minutes its done. 1.2 GB dumped.

![image](https://github.com/user-attachments/assets/8a636b20-a041-4364-9afd-6ac80f0f2fc3)

This is where I got stuck and looked for help from wiriteup submitted by ksyksy

Looks like I have to feed these file into EvtxECmd.exe

![image](https://github.com/user-attachments/assets/6c13ce9a-8f21-4b2a-a9ac-757488595f0b)

![image](https://github.com/user-attachments/assets/a654b477-7b6c-4ee9-8f06-367ddd1ae0a9)

I run

EvtxECmd.exe -f C:\Users\Administrator\Desktop\dump\file.0xde85619117d0.
0xde85618b4b70.DataSectionObject.Security.evtx.dat" --csv C:\Users\Administrator\Desktop" --csvf Security.evtx.csv

![image](https://github.com/user-attachments/assets/f316737d-f8a0-478e-ada5-592d242316bf)

Once that is completed I run 

EvtxECmd.exe -f “C:\Users\Administrator\Desktop\file.0xde8561a364a0.0xde8561a80c30.
SharedCacheMap.Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx” --csv C:\Users\Administrator\Desktop" --csvf RdpCoreTS.evtx.csv

I open the file in timeline explorer and look for Event ID 4625 (failed logon) 2 events. 

![image](https://github.com/user-attachments/assets/f7255a99-29bb-400d-8a9b-07280ad09899)

Here I find the answer. 192.168.60.129

![image](https://github.com/user-attachments/assets/71f64bc3-a96c-47f6-a777-7419c996ced3)

Question: Identifying the process name of the attacker's tool is key to tracking their actions. What is the process name of the tool used by the attacker to remotely execute commands and perform malicious activities on the compromised FileServer? Tip: Check both active and terminated or hidden processes in the memory capture.

I’m gonna move back into Volatility folder and run psscan. 

Python vol.py -f memory.dmp windows.psscan

![image](https://github.com/user-attachments/assets/5bef211b-1606-4b65-ad9e-73011b523df3)

PSEXESVC.exe stands out. A quick search reveals “Psexesvc.exe is an executable file that runs the Sysinternals PsExec utility, useful for remotely executing processes on other systems.“

Questions: Identifying the attacker's initial commands reveals their intentions and the level of access they gained. What was the first command executed remotely to begin system enumeration?

I open up the sysmon log in Timeline Explorer. Under payload data I filter for PSEXESVC and go in chronological order.

The first command can be seen here. Tasklist

![image](https://github.com/user-attachments/assets/cc1d9757-6d43-416c-9a5d-cd8a09459110)

Question: Understanding how the attacker disabled security measures is key to assessing how they gained persistence and weakened the system's defenses. The attacker used a remote execution tool, which generates a different Process ID (PID) for each command executed. What is the Process ID (PID) of the first command used to turn off Windows Defender?

I look for commands like disable involving the parent process  PSEXESVC
We can see attacker disabled Windows Defender here. PID is 5344

![image](https://github.com/user-attachments/assets/59ee4d0f-9568-4c71-9cc0-ba96e0c0d126)

Question: Identifying changes to the system's registry is essential for understanding how the attacker disabled security features, allowing malicious actions to proceed undetected. In an attempt to disable Windows Defender, the attacker modified a specific registry value. What is the name of the registry value that was added or modified under HKLM\SOFTWARE\Policies\Microsoft\Windows Defender?

Again everything the attacker did was done remotely with commands. Under executable info we can see DisableAntiSpyware

![image](https://github.com/user-attachments/assets/93c73468-26c7-4023-b4d0-0818deebc067)

Question: Understanding how the attacker leveraged specific system files is crucial, as it can reveal their methods for accessing sensitive data and escalating privileges. What DLL file did the attacker use in the PowerShell command to dump the targeted process for further exploitation?

Under executable I filter for DLL files. The answer is comsvcs.dll

![image](https://github.com/user-attachments/assets/3f5e9c00-ea9a-4c37-a6dd-6c9214ae6ac4)

Question: Investigating the creation of new accounts is crucial for identifying how the attacker maintains unauthorized access to the system. To establish persistent access, the attacker created a new user account on the compromised system. What is the name of the account that the attacker created?

Creating a new user falls under Event ID 4720 and those would get logged under Security. 

I switch to those logs in Timeline Explorer. I filter for Event ID 4720. under payload I find the answer. ITadmin_2

![image](https://github.com/user-attachments/assets/71bc8c13-e3b9-4230-a791-68443c731690)

Question: Identifying the URL in the ransom note is vital for understanding the attacker's communication and data exposure threats. The attacker included a link to their blog where stolen data would be published if negotiations fail. What is the URL provided for communication and accessing the attacker's chat?

I use bstrings to look for any URLs in the memory dump. This takes a while.

bstrings -f memory.dmp --ls URL -o "C:\Users\Administrator\Desktop\Ransom.txt

![image](https://github.com/user-attachments/assets/21b0675b-7b58-49be-b16e-efbc11d515d3)


