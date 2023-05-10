import xml.etree.ElementTree as ET
from colorama import Fore, Style
import re
import argparse
import json
from colorama import Fore, Style, init
from collections import defaultdict
from termcolor import colored

def log_initialize(xml_file_path):

  tree = ET.parse(xml_file_path)
  root = tree.getroot()

  global outerdic
  outerdic = {}
  i = 0

  for event in root:

    i = i+1
    sysdic = {}
    eventdic = {}
    userdic = {}
    innerdic = {}

    for item in event:

      item_tag = item.tag
      itemkey = item_tag[item_tag.rindex("}")+1:]

      if itemkey == "System":

        for sub_item in item:
          value = sub_item.text
          sub_item_tag = sub_item.tag
          attributes = sub_item.attrib
          key = sub_item_tag[sub_item_tag.rindex("}")+1:]
          if key == "Provider":
            sysdic["Provider Name"] = attributes["Name"]
            try:
              sysdic["Provider Guid"] = attributes["Guid"]
              continue
            except:
              continue
          elif key == "TimeCreated":
            sysdic["TimeCreated SystemTime"] = attributes["SystemTime"]
            continue
          elif key == "Execution":
            sysdic["Execution ThreadID"] = attributes["ThreadID"]
            sysdic["Execution ProcessID"] = attributes["ProcessID"]
            continue
          elif key == "Correlation":
            try:
              sysdic["Correlation ActivityID"] = attributes["ActivityID"]
              continue
            except:
              pass
          elif key == "Security":
            try:
              sysdic["Security UserID"] = attributes["UserID"]
              continue
            except:
              pass
          sysdic[key] = value

      elif itemkey == "EventData":

        for sub_item in item:
          value = sub_item.text
          sub_item_tag = sub_item.tag
          attributes = sub_item.attrib
          key = sub_item_tag[sub_item_tag.rindex("}")+1:]
          if key == "Data":
            try:
              key = attributes['Name']
            except:
              pass
          eventdic[key] = value

      elif itemkey == "UserData":

        for sub_event in item:
          for sub_sub_item in sub_event:
            value = sub_sub_item.text
            sub_sub_item_tag = sub_sub_item.tag
            key = sub_sub_item_tag[sub_sub_item_tag.rindex("}")+1:]
            userdic[key] = value

    innerdic["System"] = sysdic
    innerdic["EventData"] = eventdic
    innerdic["UserData"] = userdic

    outerdic[i] = innerdic

# Pretty print logs
"""
def pretty_print_logs(xml_file_path):
  log_initialize(xml_file_path)
  print(json.dumps(outerdic, indent=2))
"""

# User Creation and Added/Removed User to Admin group. Also check if any other existing users were added/removed to the Admin group. Also check if any user was deleted.

def detect_user_account_activity(security_log_path):

  log_initialize(security_log_path)

  userAddSIDs = set()
  userRemSIDs = set()

  for k in outerdic:
    if outerdic[k]["System"]["EventID"] == "4720":
      print(Fore.BLUE + "New user", outerdic[k]["EventData"]["TargetUserName"], "created with SID", outerdic[k]["EventData"]["TargetSid"] + Style.RESET_ALL)
      SID = outerdic[k]["EventData"]["TargetSid"]

      for n in outerdic:

        if outerdic[n]["System"]["EventID"] == "4732" and outerdic[n]["EventData"]["TargetUserName"] == "Administrators" and outerdic[n]["EventData"]["MemberSid"] == SID:
          print(Fore.BLUE + "User", outerdic[k]["EventData"]["TargetUserName"], "was added to the local Administrators group" + Style.RESET_ALL)
          userAddSIDs.add(outerdic[n]["EventData"]["MemberSid"])

  for k in outerdic:
    if outerdic[k]["System"]["EventID"] == "4720":
      SID = outerdic[k]["EventData"]["TargetSid"]

      for n in outerdic:

        if outerdic[n]["System"]["EventID"] == "4733" and outerdic[n]["EventData"]["TargetUserName"] == "Administrators" and outerdic[n]["EventData"]["MemberSid"] == SID:
            print(Fore.BLUE + "User", outerdic[k]["EventData"]["TargetUserName"], "was removed from the local Administrators group" + Style.RESET_ALL)
            userRemSIDs.add(outerdic[n]["EventData"]["MemberSid"])

  for m in outerdic:
    if outerdic[m]["System"]["EventID"] == "4732" and outerdic[m]["EventData"]["TargetUserName"] == "Administrators" and (outerdic[m]["EventData"]["MemberSid"] not in userAddSIDs):
      print(Fore.BLUE + "User with SID", outerdic[m]["EventData"]["MemberSid"], "was added to the local Administrators group" + Style.RESET_ALL)

  for t in outerdic:
    if outerdic[t]["System"]["EventID"] == "4733" and outerdic[t]["EventData"]["TargetUserName"] == "Administrators" and (outerdic[t]["EventData"]["MemberSid"] not in userRemSIDs):
      print(Fore.BLUE + "User with SID", outerdic[t]["EventData"]["MemberSid"], "was removed from the local Administrators group" + Style.RESET_ALL)

  for d in outerdic:
    if outerdic[d]["System"]["EventID"] == "4726":
      print(Fore.BLUE + "User", outerdic[d]["EventData"]["TargetUserName"], "was deleted." + Style.RESET_ALL)

# Detection of malicious executable

def detect_malicious_executable(sysmon_log_path, hash_file):

  log_initialize(sysmon_log_path)

  with open(hash_file, "r") as file:
      hash_list = [line.strip() for line in file]

  uniq = []

  for k in outerdic:

    if outerdic[k]["System"]["EventID"] == "1":

      image = outerdic[k]["EventData"]["Image"]

      if image not in uniq:

        uniq.append(image)

        hashes = outerdic[k]["EventData"]["Hashes"]
        md5_start_index = hashes.find("MD5=") + len("MD5=")
        md5_end_index = hashes.find(",", md5_start_index)
        md5_hash = hashes[md5_start_index:md5_end_index]

        if md5_hash.lower() in hash_list:
          print(Fore.RED + f"{image} is malicious and was ran by", outerdic[k]["EventData"]["User"])

# Detecting SMB brute-force

def detect_smb_bruteforce(smb_security_log_path, security_log_path=None, sysmon_log_path=None):

  log_initialize(smb_security_log_path)

  temp_clients = []
  smb_clients = {}

  max = 10

  for k in outerdic:

    if outerdic[k]["System"]["EventID"] == "551":

      client_name = outerdic[k]["UserData"]["ClientName"]

      if client_name not in temp_clients:
        temp_clients.append(client_name)
        count = 0
        for j in outerdic:
          if outerdic[j]["System"]["EventID"] == "551" and outerdic[j]["UserData"]["ClientName"] == client_name:
            count = count+1
            smb_clients[client_name] = count

            if smb_clients[client_name] > max:
              break

  for client_name in smb_clients:
    if smb_clients[client_name] > max:
      print(Fore.RED + "High number of failed login attempts on SMB from", client_name + Style.RESET_ALL)
      target_user = []
      for k in outerdic:
        if outerdic[k]["System"]["EventID"] == "551" and outerdic[k]["UserData"]["ClientName"] == client_name:
          username = outerdic[k]["UserData"]["UserName"]
          if username not in target_user:
            target_user.append(username)
            if len(target_user) > 1:
              print(Fore.RED + f"The attacker ({client_name}) is targeting multiple users, probabaly using a user list." + Style.RESET_ALL)
              break
      if len(target_user) == 1:
        print(Fore.RED + f"The attacker ({client_name}) is targeting this user:", target_user[0] + Style.RESET_ALL)
  
  if security_log_path is not None and sysmon_log_path is not None:
  
    log_initialize(security_log_path)

    for client_name in smb_clients:
      if smb_clients[client_name] > max:
        for k in outerdic:
          if outerdic[k]["System"]["EventID"] == "4624":
            if outerdic[k]["EventData"]["WorkstationName"] == client_name:
              # possible compromise
              ip_address = outerdic[k]["EventData"]["IpAddress"]
              ip_port = outerdic[k]["EventData"]["IpPort"]
              user_compromised = outerdic[k]["EventData"]["TargetUserName"]

              log_initialize(sysmon_log_path)

              for j in outerdic:
                if outerdic[j]["System"]["EventID"] == "3" and outerdic[j]["EventData"]["DestinationPort"] == "445":
                  if outerdic[j]["EventData"]["SourceIp"] == ip_address and outerdic[j]["EventData"]["SourcePort"] == ip_port:
                    print(Fore.RED + f"Your system has been compromised! SMB login success detected from {client_name} for user:", user_compromised + Style.RESET_ALL)
                    break
  else:
    print(Fore.BLUE + "To know if any account has been compromised, please provide the additional Security log and Sysmon log as well." + Style.RESET_ALL)

# Detecting RDP brute force

def detect_rdp_bruteforce(security_log_path, rpd_core_log_path, rdp_remoteconn_manager_log_path=None):

  log_initialize(security_log_path)

  client_ip = []
  rdp_clients = {}

  max = 10

  for k in outerdic:
    if outerdic[k]["System"]["EventID"] == "4625":
      ip = outerdic[k]["EventData"]["IpAddress"]
      if ip not in client_ip:
        client_ip.append(ip)

        count = 0
        for j in outerdic:
          if outerdic[j]["System"]["EventID"] == "4625" and outerdic[j]["EventData"]["IpAddress"] == ip:
            count = count + 1
            rdp_clients[ip] = count

            if rdp_clients[ip] > max:
              break

  log_initialize(rpd_core_log_path)

  sus_ip = []

  for ip in rdp_clients:
    if rdp_clients[ip] > max:
      counter = 0
      for k in outerdic:
        if outerdic[k]["System"]["EventID"] == "131":
          cip = outerdic[k]["EventData"]["ClientIP"]
          cip_only = cip.split(":")[0]

          if cip_only == ip:
            counter = counter + 1
            if counter > max:
              print(Fore.RED + "Possible RDP brute force attack by", ip + Style.RESET_ALL)
              sus_ip.append(ip)
              break

  if rdp_remoteconn_manager_log_path is not None:
    
    log_initialize(rdp_remoteconn_manager_log_path)

    for ip in sus_ip:
      for k in outerdic:
        if outerdic[k]["System"]["EventID"] == "1149" and outerdic[k]["UserData"]["Param3"] == ip:
          print(Fore.RED + "Your system may have been compromised as a successful RDP login was detected for user", outerdic[k]["UserData"]["Param1"], "by", ip + Style.RESET_ALL)
  else:
    print(Fore.BLUE + "To know if any account has been compromised, please provide the additional Remote Connection Manager log as well." + Style.RESET_ALL)

# Detecting WinRM brute-force

def detect_winrm_bruteforce(winrm_logs_path):

  log_initialize(winrm_logs_path)

  max = 10
  count = 0

  for k in outerdic:
    if outerdic[k]["System"]["EventID"] == "162":
      count = count + 1
      if count > max:
        print(Fore.RED + "WinRM brute-force attack detected")
        break

# Detecting suspicious services

def detect_suspicious_services(sysmon_log_path, system_log_path):

  log_initialize(sysmon_log_path)

  prefix = "HKLM\\System\\CurrentControlSet\\Services\\"

  for k in outerdic:
    if outerdic[k]["System"]["EventID"] == "12" and outerdic[k]["EventData"]["EventType"] == "CreateKey":
      target_object = outerdic[k]["EventData"]["TargetObject"]
      if target_object.startswith(prefix):
        print(Fore.BLUE + "New service object created:", target_object, "by", outerdic[k]["EventData"]["User"] + Style.RESET_ALL)

        target_object = target_object + "\\ImagePath"
        for j in outerdic:
          if outerdic[j]["System"]["EventID"] == "13" and outerdic[j]["EventData"]["TargetObject"] == target_object:
            path = outerdic[j]["EventData"]["Details"]
            if not path.startswith('\"C:\\Program Files (x86)\\') or path.startswith('\"C:\\Program Files\\'):
              print(Fore.RED + "Suspicious image path for service", target_object.split(prefix)[1].split("\\")[0], "(executable/payload):" + Style.RESET_ALL, path)

  print("--------------------------------------------------------------------------")

  log_initialize(system_log_path)

  print("Services started ----------------------------")
  for k in outerdic:
    if outerdic[k]["System"]["EventID"] == "7036":
      if outerdic[k]["EventData"]["param2"] == "running":
        print(Fore.GREEN + outerdic[k]["EventData"]["param1"], "is running." + Style.RESET_ALL)

  print("Services stopped -----------------------------")
  for k in outerdic:
    if outerdic[k]["System"]["EventID"] == "7036":
      if outerdic[k]["EventData"]["param2"] == "stopped":
        print(Fore.BLUE + outerdic[k]["EventData"]["param1"], "has stopped." + Style.RESET_ALL)

  print("--------------------------------------------------------------------------")

  log_initialize(sysmon_log_path)

  for k in outerdic:
    if outerdic[k]["System"]["EventID"] == "13":
      target_object = outerdic[k]["EventData"]["TargetObject"]
      if target_object.startswith(prefix) and target_object.endswith("Start"):
        if outerdic[k]["EventData"]["Details"] == "DWORD (0x00000004)":
          print(Fore.BLUE + "Service disabled: ", target_object.split(prefix)[1].split("\\")[0] + Style.RESET_ALL)

  # https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Services-and-drivers.html

  for k in outerdic:
    if outerdic[k]["System"]["EventID"] == "12" and outerdic[k]["EventData"]["EventType"] == "DeleteKey":
      target_object = outerdic[k]["EventData"]["TargetObject"]
      if target_object.startswith(prefix):
        print(Fore.BLUE + "Service object deleted:", target_object, "by", outerdic[k]["EventData"]["User"] + Style.RESET_ALL)

# Detecting PTH attack

# VERSION 1
# Source host 
def detect_pth_attack(security_log_path, sysmon_log_path):

  log_initialize(security_log_path)

  for k in outerdic:
    if outerdic[k]["System"]["EventID"] == "4624":
      if outerdic[k]["EventData"]["LogonType"] == "9" and outerdic[k]["EventData"]["LogonProcessName"] == "seclogo" and outerdic[k]["EventData"]["AuthenticationPackageName"] == "Negotiate":

        log_initialize(sysmon_log_path)

        if outerdic[k]["System"]["EventID"] == "10":
          if outerdic[k]["EventData"]["TargetImage"].lower() == "c:\\windows\\system32\\lsass.exe" and outerdic[k]["EventData"]["GrantedAccess"] == "0x1010" or "0x1038":

            print(Fore.RED + "Possible Pass the Hash attack detected!" + Style.RESET_ALL)
            
# VERSION 2
"""
def detect_pth_attack(security_log_path):

  log_initialize(security_log_path)

  for k in outerdic:
     if outerdic[k]["System"]["EventID"] == "4624" and outerdic[k]["EventData"]["AuthenticationPackageName"] == "NTLM":
        print(Fore.RED + "Possible pass-the-hash attack detected!" + Style.RESET_ALL)
"""   
        
# Detect Registry changes

def detect_registry_changes(sysmon_log):

    log_initialize(sysmon_log)

    registryRegex = re.compile(
        r'SetValue|CreateKey|DeleteValue"|DeleteKey', re.IGNORECASE)

    # Add known suspicious registry paths related to various techniques
    suspicious_registry_paths = {
        'Clear-text credential dumping': [
            r"HKLM\Security\Cache",
            r"HKLM\System\CurrentControlSet\Control\Lsa",
            r"HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest",
            r"HKLM\System\CurrentControlSet\Control\Lsa\CredentialEnumerationFilters",
            r"HKLM\System\CurrentControlSet\Control\Lsa\Kerberos",
            r"HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0",
            r"HKLM\System\CurrentControlSet\Control\Lsa\SspiCache",
        ],
        'Encrypting File System (EFS) settings': [
            r"HKLM\Software\Microsoft\EFS",
        ],
        'Terminal Services Session (RDP) hijacking': [
            r"HKLM\System\CurrentControlSet\Services\TsSessions\PerSession\Services\wdm",
        ],
        'Persistence through Run and RunOnce keys': [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\(Default)",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\(Default)",
        ],
        'Persistence through Scheduled Tasks': [
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
        ],
        'Disabling Windows Defender and other security products': [
            r"HKLM\Software\Policies\Microsoft\Windows Defender",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore",
        ],
        'Persistence through AppInit_DLLs': [
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
        ],
        'Persistence through Winlogon Shell': [
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        ],
        'Persistence through Winlogon Userinit': [
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        ],
        'Persistence through Explorer Run key': [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        ],
        'Persistence through Screensaver': [
            r"HKCU\\[Cc]ontrol\sPanel\\Desktop\\SCRNSAVE\.EXE",
            r"HKU\\.DEFAULT\\[Cc]ontrol\sPanel\\Desktop\\SCRNSAVE\.EXE",
            r"HKU\\S-1-5-21-\d+-\d+-\d+-\d+\\[Cc]ontrol\sPanel\\Desktop\\SCRNSAVE\.EXE",
            r"HKU\\S-1-5-21-\d+-\d+-\d+-\d+\\[Cc]ontrol\sPanel\\Desktop\\WallPaper",
            r"HKU\\S-1-5-21-\d+-\d+-\d+-\d+\\[Cc]ontrol\sPanel\\Desktop\\WallPaper2",
        ],
        'Disabling UAC': [
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        ],
        'Disabling Windows Firewall': [
            r"HKLU\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy",
        ],
        'Always Install Elevated Policies': [
            r"HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer",
        ],
        'PowerShell Policies and Services': [
            r"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell",
        ],
        'WMI Remote Access': [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\wmipers",
        ],
        'CVE-2020-1313': [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\51999\queuedTime",
        ],
        'Rundll32 Cmd Schtask': [
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data\418A073AA3BC3475",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager",
        ],
        'PanacheSysmon vs AtomicRedTeam': [
            r"HKLM\System\CurrentControlSet\Services\AtomicTestService\Start",
            r"HKLM\System\CurrentControlSet\Services\AtomicTestService\ImagePath",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\NextRun",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\Debugger",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\Debugger",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe\Debugger",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe\Debugger",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe\Debugger",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\atbroker.exe\Debugger",
        ],
        'RDP Setting Tampering': [
            r"HKLM\System\CurrentControlSet\services\TermService\Parameters\ServiceDll",
            r"HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections",
            r"HKLM\System\CurrentControlSet\Control\Terminal Server\Licensing Core\EnableConcurrentSessions",
            r"HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber",
        ],
        'Lanmar Server Network Added': [
            r"HKLM\System\CurrentControlSet\Services\LanmanServer\Shares\staging",
            r"HKLM\System\CurrentControlSet\Services\LanmanServer\Shares\Security",
            r"HKLM\System\CurrentControlSet\Services\LanmanServer\Shares\Security\staging",
        ],
        'Persisting in svchost.exe with a Service DLL': [
            r"HKLM\System\CurrentControlSet\Services\W32Time\Config\LastKnownGoodTime",
            r"HKLM\System\CurrentControlSet\Services\EvilSvc\Parameters\ServiceDll",
            r"HKLM\System\CurrentControlSet\Services\EvilSvc\Parameters",
            r"HKLM\System\CurrentControlSet\Services\EvilSvc\ObjectName",
            r"HKLM\System\CurrentControlSet\Services\EvilSvc\ImagePath",
            r"HKLM\System\CurrentControlSet\Services\EvilSvc\ErrorControl",
            r"HKLM\System\CurrentControlSet\Services\EvilSvc\Start",
            r"HKLM\System\CurrentControlSet\Services\EvilSvc\Type",
        ],
        'Suspicious NetSh Helper DLL': [
            r"HKLM\SOFTWARE\Microsoft\NetSh\NetshHelperBeacon",
            r"HKLM\SOFTWARE\Microsoft\NetSh",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports\Ne01",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports\Ne00",
            r"HKLM\System\CurrentControlSet\Services\SharedAccess\Epoch",
            r"HKLM\System\CurrentControlSet\Services\mpssvc\Parameters\AppCs\AppCs",
        ],
    }

    changes_detected = False

    for k in outerdic:
        event_id = outerdic[k]["System"].get("EventID", "N/A")
        image = outerdic[k]["EventData"].get("Image", "N/A")
        user = outerdic[k]["System"].get("Computer", "N/A")
        if event_id in ["12", "13", "14"]:
            if mo1 := registryRegex.search(outerdic[k]["EventData"]["EventType"]):
                target_object = outerdic[k]["EventData"].get(
                    "TargetObject", "N/A")
                detected_activity = None
                for activity, paths in suspicious_registry_paths.items():
                    if any(path in target_object for path in paths):
                        detected_activity = activity
                        break

                if detected_activity:
                    changes_detected = True
                    print(
                        Fore.RED + f"---Possible {detected_activity} detected---" + Style.RESET_ALL)
                    print(Fore.GREEN + "Computer Name:" + Style.RESET_ALL, user)
                    print(Fore.BLUE + "Event Type:" + Style.RESET_ALL,
                          outerdic[k]["EventData"].get("EventType", "N/A"))
                    print(Fore.BLUE + "Image:" + Style.RESET_ALL, image)
                    print(Fore.BLUE + "Timestamp:" + Style.RESET_ALL,
                          outerdic[k]["EventData"].get("UtcTime", "N/A"))
                    print(Fore.BLUE + "Target Object:" +
                          Style.RESET_ALL, target_object)
                    print()

    # To track the count of registry changes made by different users and processes in the given Windows event logs

    user_count = defaultdict(int)
    process_count = defaultdict(int)

    for k in outerdic:
        event_id = outerdic[k]["System"]["EventID"]
        if event_id in ["12", "13", "14"]:
            user = outerdic[k]["System"].get("Computer", "N/A")
            image = outerdic[k]["EventData"]["Image"]
            target_object = outerdic[k]["EventData"]["TargetObject"]

            user_count[user] += 1
            process_count[image] += 1

    # You can set a threshold for the number of registry changes
    user_threshold = 5
    process_threshold = 5

    for user, count in user_count.items():
        if count > user_threshold:
            print(
                Fore.RED + "---Suspicious registry changes by user detected---" + Style.RESET_ALL)
            print(Fore.GREEN + "Computer Name:" + Style.RESET_ALL, user)
            print(Fore.BLUE + "Number of changes:" + Style.RESET_ALL, count)
            print()

    for image, count in process_count.items():
        if count > process_threshold:
            print(
                Fore.RED + "---Suspicious registry changes by process detected---" + Style.RESET_ALL)
            print(Fore.GREEN + "Triggered by process:" + Style.RESET_ALL, image)
            print(Fore.BLUE + "Number of changes:" + Style.RESET_ALL, count)
            print() 
    
    if not changes_detected:
        print(Fore.YELLOW + "No suspicious registry changes detected." + Style.RESET_ALL)
        print()

# Detect Suspicious Powershell Downloads
def detect_suspicious_download(sysmon_log):

    log_initialize(sysmon_log)

    downloadRegex = re.compile(
        r'DownloadString|downloadfile|System.Net.WebClient|system.net.webclient', re.IGNORECASE)
    attack_detected = False

    for k in outerdic:
        if outerdic[k]["System"]["EventID"] == "1" and outerdic[k]["EventData"]["Image"] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe":
            if mo1 := downloadRegex.search(outerdic[k]["EventData"]["CommandLine"]):
                attack_detected = True
                print(
                    Fore.RED + "---Suspicious Powershell download detected---" + Style.RESET_ALL)
                print(Fore.GREEN + "Triggered by user:" +
                      Style.RESET_ALL, outerdic[k]["EventData"]["User"])
                print(Fore.BLUE + "Through command:" + Style.RESET_ALL,
                      outerdic[k]["EventData"]["CommandLine"])
                print()

    if not attack_detected:
        print(Fore.YELLOW + "No suspicious Powershell downloads detected." + Style.RESET_ALL)
        print()

# Detect Suspicious Executables
def detect_suspicious_executable(sysmon_log):

    log_initialize(sysmon_log)

    rundll32Regex = re.compile(
        r'DownloadString|malware|javascript|url.dll|OpenURL|RegisterXLL', re.IGNORECASE)
    wscriptRegex = re.compile(
        r'DownloadString|javascript|vba|jse|js|vbs', re.IGNORECASE)
    cscriptRegex = re.compile(
        r'DownloadString|javascript|vba|jse|js|vbs', re.IGNORECASE)
    mshtaRegex = re.compile(
        r'DownloadString|CreateObject|Execute|jpg|png|lnk|xls|doc|zip', re.IGNORECASE)
    scRegex = re.compile(
        r'DownloadString|malware|javascript|url.dll|OpenURL', re.IGNORECASE)
    certutilRegex = re.compile(
        r'urlcache|-f|-split|-decode|-encode', re.IGNORECASE)
    bitsadminRegex = re.compile(
        r'/transfer|/download|/priority', re.IGNORECASE)
    executables_detected = False

    for k in outerdic:
        if outerdic[k]["System"]["EventID"] == "1":
            image = outerdic[k]["EventData"]["Image"]
            command_line = outerdic[k]["EventData"]["CommandLine"]
            current_executable_detected = False
            if image.lower() == "c:\\windows\\system32\\rundll32.exe" or image.lower() == "c:\\windows\\syswow64\\rundll32.exe" and rundll32Regex.search(command_line):
                current_executable_detected = True
                print(
                    Fore.RED + "---Suspicious Powershell executable rundll32.exe detected---" + Style.RESET_ALL)
                print(Fore.GREEN + "Triggered by user:" +
                      Style.RESET_ALL, outerdic[k]["EventData"]["User"])
                print(Fore.BLUE + "Through command:" +
                      Style.RESET_ALL, command_line)
                print()

            elif image.lower() == "c:\\windows\\system32\\wscript.exe" and wscriptRegex.search(command_line):
                current_executable_detected = True
                print(
                    Fore.RED + "---Suspicious Powershell executable wscript.exe detected---" + Style.RESET_ALL)
                print(Fore.GREEN + "Triggered by user:" +
                      Style.RESET_ALL, outerdic[k]["EventData"]["User"])
                print(Fore.BLUE + "Through command:" +
                      Style.RESET_ALL, command_line)
                print()

            elif image.lower() == "c:\\windows\\system32\\cscript.exe" or image.lower() == "c:\\windows\\syswow64\\cscript.exe" and cscriptRegex.search(command_line):
                current_executable_detected = True
                print(
                    Fore.RED + "---Suspicious Powershell executable cscript.exe detected---" + Style.RESET_ALL)
                print(Fore.GREEN + "Triggered by user:" +
                      Style.RESET_ALL, outerdic[k]["EventData"]["User"])
                print(Fore.BLUE + "Through command:" +
                      Style.RESET_ALL, command_line)
                print()

            elif image.lower() == "c:\\windows\\system32\\mshta.exe" and mshtaRegex.search(command_line):
                current_executable_detected = True
                print(
                    Fore.RED + "---Suspicious Powershell executable mshta.exe detected---" + Style.RESET_ALL)
                print(Fore.GREEN + "Triggered by user:" +
                      Style.RESET_ALL, outerdic[k]["EventData"]["User"])
                print(Fore.BLUE + "Through command:" +
                      Style.RESET_ALL, command_line)
                print()

            elif image.lower() == "c:\\windows\\system32\\sc.exe" and scRegex.search(command_line):
                current_executable_detected = True
                print(
                    Fore.RED + "---Suspicious Powershell executable sc.exe detected---" + Style.RESET_ALL)
                print(Fore.GREEN + "Triggered by user:" +
                      Style.RESET_ALL, outerdic[k]["EventData"]["User"])
                print(Fore.BLUE + "Through command:" +
                      Style.RESET_ALL, command_line)
                print()

            elif image.lower() == "c:\\windows\\system32\\certutil.exe" and certutilRegex.search(command_line):
                current_executable_detected = True
                print(
                    Fore.RED + "---Suspicious executable certutil.exe detected---" + Style.RESET_ALL)
                print(Fore.GREEN + "Triggered by user:" +
                      Style.RESET_ALL, outerdic[k]["EventData"]["User"])
                print(Fore.BLUE + "Through command:" +
                      Style.RESET_ALL, command_line)
                print()

            elif image.lower() == "c:\\windows\\system32\\bitsadmin.exe" and bitsadminRegex.search(command_line):
                current_executable_detected = True
                print(
                    Fore.RED + "---Suspicious executable bitsadmin.exe detected---" + Style.RESET_ALL)
                print(Fore.GREEN + "Triggered by user:" +
                      Style.RESET_ALL, outerdic[k]["EventData"]["User"])
                print(Fore.BLUE + "Through command:" +
                      Style.RESET_ALL, command_line)
                print()
            
            if current_executable_detected:
                executables_detected = True

    if not executables_detected:
        print(Fore.YELLOW + "No suspicious executables detected." + Style.RESET_ALL)
        print()

#Detect Mimikatz
def detect_mimikatz(sysmon_log,security_log=None):

    log_initialize(sysmon_log)

    mimikatz_exe_regex = re.compile(r'(mimikatz\.exe)', re.IGNORECASE)
    mimikatz_cmd_regex = re.compile(
        r'(privilege::debug|sekurlsa::logonpasswords|lsadump::sam)', re.IGNORECASE)
    gentilkiwi_regex = re.compile(r'(gentilkiwi)', re.IGNORECASE)
    attack_detected = False

    # Mimikatz access mask values and descriptions
    mimikatz_access_masks = {
        0x1438: 'lsadump::lsa /patch, lsadump::trust /patch, misc:memssp',
        0x143a: 'lsadump::lsa /inject',
        0x1fffff: 'Procdump mimidump, Task Manage minidump',
        0x1400: 'Task Manage minidump',
        0x1000: 'Task Manage minidump',
        0x1410: 'Task Manage minidump',
        0x1010: 'sekurlsa::*'
    }

    results = {}

    for k in outerdic:
        event_id = int(outerdic[k]["System"]["EventID"])
        timestamp = outerdic[k]["EventData"].get("UtcTime", "N/A")

        if event_id == 10:
            image = outerdic[k]["EventData"].get("SourceImage", "")
            target_image = outerdic[k]["EventData"].get("TargetImage", "")
            access_mask = outerdic[k]["EventData"].get("GrantedAccess", "N/A")

            if "mimikatz" in image or "lsass.exe" in target_image or access_mask in mimikatz_access_masks:
                results[timestamp] = {
                    "event_id": event_id,
                    "image": image,
                    "target_image": target_image,
                    "access_mask": access_mask
                }
                attack_detected = True

        if event_id == 1:
            image = outerdic[k]["EventData"]["Image"]
            command_line = outerdic[k]["EventData"].get("CommandLine", "")
            company = outerdic[k]["EventData"].get("Company", "N/A")

            if (
                mimikatz_exe_regex.search(image)
                or mimikatz_exe_regex.search(command_line)
                or mimikatz_cmd_regex.search(command_line)
            ) or gentilkiwi_regex.search(company):
                user = outerdic[k]["EventData"]["User"]
                print(Fore.RED + "---Mimikatz attack detected---" + Style.RESET_ALL)
                print(Fore.GREEN + "Triggered by user:" + Style.RESET_ALL, user.strip())
                print(Fore.BLUE + "Image:" + Style.RESET_ALL, image.strip())
                print(Fore.BLUE + "Command line:" +
                      Style.RESET_ALL, command_line.strip())
                print(Fore.BLUE + "Company Name:" + Style.RESET_ALL, company.strip())
                print()
                attack_detected = True

    if results:
        print(Fore.RED + "---Credential Dump Attempted---" + Style.RESET_ALL)
        for timestamp, result in results.items():
            access_mask_int = int(result["access_mask"], 16)  # Convert the access mask to an integer
            access_mask_info = mimikatz_access_masks.get(access_mask_int, "Unknown access mask")  # Get the corresponding description
            
            print(Fore.GREEN + "Timestamp:" + Style.RESET_ALL, timestamp.strip())
            print(Fore.BLUE + "Event ID:" +
                  Style.RESET_ALL, result["event_id"])
            print(Fore.BLUE + "Image:" + Style.RESET_ALL, result["image"].strip())
            print(Fore.BLUE + "Target Image:" +
                  Style.RESET_ALL, result["target_image"].strip())
            print(Fore.BLUE + "Access Mask:" +
                  Style.RESET_ALL, result["access_mask"].strip())
            print(Fore.BLUE + "Action Triggered:" +
                  Style.RESET_ALL, access_mask_info)  # Print the access mask description
            print()


    if not attack_detected:
        print(Fore.YELLOW + "No Mimikatz attack detected." + Style.RESET_ALL)

    if security_log is not None:

      log_initialize(security_log)

      results = {}

      for k in outerdic:
          event_id = outerdic[k]["System"].get("EventID")
          if event_id == "4672" or "4673":
              subject_user_sid = outerdic[k]["EventData"].get(
                  "SubjectUserSid", "N/A")
              subject_user_name = outerdic[k]["EventData"].get(
                  "SubjectUserName", "N/A")
              subject_domain_name = outerdic[k]["EventData"].get(
                  "SubjectDomainName", "N/A")
              subject_logon_id = outerdic[k]["EventData"].get(
                  "SubjectLogonId", "N/A")
              privilege_list = outerdic[k]["EventData"].get(
                  "PrivilegeList", "N/A")
              timestamp = outerdic[k]["System"].get("TimeCreated SystemTime", "N/A")

              if subject_user_sid != "N/A":
                  if subject_user_sid not in results:
                      results[subject_user_sid] = {
                          "domain_name": subject_domain_name,
                          "user_name": subject_user_name,
                          "logon_id": subject_logon_id,
                          "privilege_list": set([privilege_list]),  # Store as a set for unique privileges
                          "timestamps": set([timestamp])  # Store as a set for unique timestamps
                      }
                  else:
                      results[subject_user_sid]["privilege_list"].add(privilege_list)
                      results[subject_user_sid]["timestamps"].add(timestamp)

      if results:
          print(Fore.RED + "---Checking Users Privileges---" + Style.RESET_ALL)
          for sid, data in results.items():
              print(Fore.GREEN + "Subject User SID:" + Style.RESET_ALL, sid)
              print(Fore.GREEN + "Subject User Name:" + Style.RESET_ALL, data["user_name"])
              print(Fore.GREEN + "Subject Domain Name:" + Style.RESET_ALL, data["domain_name"])
              print(Fore.GREEN + "Subject Logon ID:" + Style.RESET_ALL, data["logon_id"])

              print(Fore.BLUE + "Privilege List:" + Style.RESET_ALL)
              for privilege in data["privilege_list"]:
                  for single_privilege in privilege.split('\n'):
                      if single_privilege.strip():
                          print("\t" + single_privilege.strip())

              # Uncomment below to show timestamps

              # print(Fore.BLUE + "Timestamps:" + Style.RESET_ALL)
              # for ts in data["timestamps"]:
              #     print("\t" + ts.strip())

              print(Fore.YELLOW + "----------------------------------------------------" + Style.RESET_ALL)
              print()
      else:
          print(Fore.GREEN + "No Privilege Assignment Detected." + Style.RESET_ALL)
    else:
      print(Fore.BLUE + "To list out users with special privileges assigned, please provide the additional Security log as well." + Style.RESET_ALL)

def main(args):

    if args.detect_registry_changes:
        detect_registry_changes(args.detect_registry_changes)

    if args.detect_mimikatz:
      if len(args.detect_mimikatz)==1 or len(args.detect_mimikatz)==2:
        detect_mimikatz(*args.detect_mimikatz)
      else:
       print("Unrecognized arguments. Check help.")

    if args.detect_suspicious_executable:
        detect_suspicious_executable(args.detect_suspicious_executable)

    if args.detect_suspicious_download:
        detect_suspicious_download(args.detect_suspicious_download)
        
    if args.detect_user_account_activity:
        detect_user_account_activity(args.detect_user_account_activity)

    if args.detect_malicious_executable:
        detect_malicious_executable(*args.detect_malicious_executable)

    if args.detect_smb_bruteforce:
      if len(args.detect_smb_bruteforce)==1 or len(args.detect_smb_bruteforce)==3:
        detect_smb_bruteforce(*args.detect_smb_bruteforce)
      else:
       print("Unrecognized arguments. Check help.")
      
    if args.detect_rdp_bruteforce:
      if len(args.detect_rdp_bruteforce) < 2:
        print("Expected at least 2 arguments. Check help.")
      elif len(args.detect_rdp_bruteforce)==2 or len(args.detect_rdp_bruteforce)==3: 
        detect_rdp_bruteforce(*args.detect_rdp_bruteforce)
      else:
         print("Unrecognized arguments. Check help.")

    if args.detect_winrm_bruteforce:
        detect_winrm_bruteforce(args.detect_winrm_bruteforce)

    if args.detect_suspicious_services:
        detect_suspicious_services(*args.detect_suspicious_services)
        
    if args.detect_pth_attack:
        detect_pth_attack(*args.detect_pth_attack)


def parse_arguments():
    logo = r"""

████████╗██╗░░██╗██████╗░███████╗░█████╗░████████╗░██████╗███████╗███████╗██╗░░██╗███████╗██████╗░
╚══██╔══╝██║░░██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔════╝██║░██╔╝██╔════╝██╔══██╗
░░░██║░░░███████║██████╔╝█████╗░░███████║░░░██║░░░╚█████╗░█████╗░░█████╗░░█████═╝░█████╗░░██████╔╝
░░░██║░░░██╔══██║██╔══██╗██╔══╝░░██╔══██║░░░██║░░░░╚═══██╗██╔══╝░░██╔══╝░░██╔═██╗░██╔══╝░░██╔══██╗
░░░██║░░░██║░░██║██║░░██║███████╗██║░░██║░░░██║░░░██████╔╝███████╗███████╗██║░╚██╗███████╗██║░░██║
░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝░░░╚═╝░░░╚═════╝░╚══════╝╚══════╝╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝
    """
    print(colored(logo))

    description_text = """
    ThreatSeeker is a comprehensive cybersecurity analysis tool designed to identify and assess potential security threats within your system. By analyzing various log files and system events, ThreatSeeker provides insight into potential attacks such as registry changes, Mimikatz detections, suspicious executables, downloads, privilege escalations, and more. In addition, the tool is equipped to identify and prevent brute force attacks on SMB, RDP, and WinRM services, along with detecting suspicious user activities and malicious executables.
    """

    usage_text = """
    
    Please provide the correct file order for each option:

    --detect-registry-changes FILE
    --detect-mimikatz FILE1 (optional FILE2)
    --detect-suspicious-executable FILE
    --detect-suspicious-download FILE
    --detect-user-account-activity FILE
    --detect-malicious-executable FILE1 FILE2
    --detect-smb-bruteforce FILE1 (optional FILE2 FILE3)
    --detect-rdp-bruteforce FILE1 FILE2 (optional FILE3)
    --detect-winrm-bruteforce FILE
    --detect-suspicious-services FILE1 FILE2
    --detect-pth-attack FILE1 FILE2

    Example:

    python threatseeker.py --smb-bruteforce smb_file1.xml smb_file2.xml smb_file3.xml
    """
    parser = argparse.ArgumentParser(
        description=colored(description_text, "white"), usage=colored(usage_text, "yellow")
    )
    
    parser.add_argument('--detect-registry-changes', metavar='FILE', help='File path for registry changes (Sysmon log)')
    parser.add_argument('--detect-mimikatz', metavar='FILE', nargs='*', help='Two file paths for Mimikatz detection (Sysmon log, Security log). The Security log is optional.')
    parser.add_argument('--detect-suspicious-executable', metavar='FILE', help='File path for suspicious executable detection (Sysmon log)')
    parser.add_argument('--detect-suspicious-download', metavar='FILE', help='File path for suspicious download detection (Sysmon log)')
    parser.add_argument('--detect-user-account-activity', metavar='FILE', help='File path for detecting user account activity (Security log)')
    parser.add_argument('--detect-malicious-executable', nargs=2, metavar='FILE', help='Two file paths for malicious executable detection (Sysmon log, Hash file)')
    parser.add_argument('--detect-smb-bruteforce', metavar='FILE', nargs='*', help='Three file paths for SMB bruteforce detection (SMB Security log, Security log, Sysmon log). The Security log and Sysmon log are optional.')
    parser.add_argument('--detect-rdp-bruteforce', metavar='FILE', nargs='*', help='Three file paths for RDP bruteforce detection (Security log, RDP Core log, Remote Connection Manager log). The Remote Connection Manager log is optional.')
    parser.add_argument('--detect-winrm-bruteforce', metavar='FILE', help='File path for WinRM bruteforce detection (WinRM log)')
    parser.add_argument('--detect-suspicious-services', metavar='FILE', nargs=2, help='Two file paths for suspicious services detection (Sysmon log, System log)')
    parser.add_argument('--detect-pth-attack', metavar='FILE', nargs=2, help='Two file paths for detecting PTH attack from source host (Security log, Sysmon log)')
    
    return parser.parse_args()

if __name__ == "__main__":
    main(parse_arguments())
