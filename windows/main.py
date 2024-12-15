import subprocess


def main():
    print("""
        -######---------------------------------#######------------------------------------
        -#-----#-#####----##---#----#--####-----#---------##----####--#------######--####--
        -#-----#-#----#--#--#--#----#-#----#----#--------#--#--#----#-#------#------#------
        -######--#----#-#----#-#----#-#----#----#####---#----#-#------#------#####---####--
        -#-----#-#####--######-#----#-#----#----#-------######-#--###-#------#-----------#-
        -#-----#-#---#--#----#--#--#--#----#----#-------#----#-#----#-#------#------#----#-
        -######--#----#-#----#---##----####-----#######-#----#--####--######-######--####--
        -----------------------------------------------------------------------------------
        --------------------------#####----###----#####--#######---------------------------
        -------------------------#-----#--#---#--#-----#-#---------------------------------
        -------------------------------#-#-----#-------#-#---------------------------------
        --------------------------#####--#-----#--#####--######----------------------------
        -------------------------#-------#-----#-#-------------#---------------------------
        -------------------------#--------#---#--#-------#-----#---------------------------
        -------------------------#######---###---#######--#####----------------------------
        """)
    choicesDict = {
        "1": func1_enable_auto_update,
        "2": func2_user_rights_assignments,
        "3": func3_start_event_log,
        "4": func4_enable_firewall,
        "5": func5_disable_enable_RDP,
        "6": func6_disable_guest_and_admin_accounts,
    }
    choice = "0"
    while choice != "q":
        choice = menu()
        action = choicesDict.get(choice)
        if choice in choicesDict.keys():
            action()
        elif choice != "q":
            print("Invalid input")

def menu():
    print("""
        1) Enable auto updates                  2) Configure user rights assignments
        3) Configure Event Log Service          4) Enable Windows Firewall
        5) Disable/Enable RDP                   6) Disable guest and Administrator accounts
        q) exit
        """)
    try:
        choice = input()
    except:
        return "q"
    return choice

def func1_enable_auto_update():
    try:
        ps_script = r"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 0"
        subprocess.run(["powershell", "-Command", ps_script], check=True)
        print("Automatic updates enabled successfully.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")

def func2_user_rights_assignments():
    user_rights = {
        f"Access Credential Manager as a trusted caller": f"No one",
        f"Access the computer from the network": f"Administrators",
        f"Act as part of the operating system": f"No one",
        f"Adjust memory quotas for a process": f"Administrators, LOCAL SERVICE, NETWORK SERVICE",
        f"Allow log on locally": f"Administrators, Users",
        f"Allow log on through Remote Desktop Services": f"Administrators, Remote Desktop Users",
        f"Back up files and directories": f"Administrators",
        f"Change system time": f"Administrators, LOCAL SERVICE",
        f"Change the time zone": f"Administrators, LOCAL SERVICE, Users",
        f"Create a pagefile": f"Administrators",
        f"Create a token object": f"No one",
        f"Create global objects": f"Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE",
        f"Create permanent shared objects": f"No one",
        f"Create symbolic links": f"Administrators",
        f"Debug programs": f"Administrators",
        f"Deny access to this computer from the network": f"Guest, Local account",
        f"Deny log on as a batch job": f"Guest",
        f"Deny log on as a service": f"Guest",
        f"Deny log on locally": f"Guest",
        f"Deny log on through Remote Desktop Services": f"Guest, Local account",
        f"Enable computer and user accounts to be trusted for delegation": f"No one",
        f"Force shutdown from a remote system": f"Administrators",
        f"Generate security audits": f"LOCAL SERVICE, NETWORK SERVICE",
        f"Impersonate a client after authentication": f"Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE",
        f"Increase scheduling priority": f"Administrators",
        f"Load and unload device drivers": f"Administrators",
        f"Lock pages in memory": f"No one",
        f"Log on as a batch job": f"Administrators",
        f"Log on as a service": f"No one",
        f"Manage auditing and security log": f"Administrators",
        f"Modify an object label": f"No one",
        f"Modify firmware environment values": f"Administrators",
        f"Perform volume maintenance tasks": f"Administrators",
        f"Profile single process": f"Administrators",
        f"Profile system performance": f"Administrators, NT SERVICE\\WdiServiceHost",
        f"Replace a process level token": f"LOCAL SERVICE, NETWORK SERVICE",
        f"Restore files and directories": f"Administrators",
        f"Shutdown the system": f"Administrators, Users",
        f"Take ownership of file or other objects": f"Administrators"
    }
    for name, users in user_rights.items():
        ps_script = f"""
        secedit /export /cfg C:\\secpol.inf
        powershell -Command "Get-Content C:\\secpol.inf | ForEach-Object {{$_ -replace '^{name}=.*', '{name}={users}'}} | Set-Content C:\\secpol.inf"
        secedit /configure /cfg C:\\secpol.inf
        """
        try:
            subprocess.run(["powershell", "-Command", ps_script], check=True)
        except subprocess.CalledProcessError as e:
            print("An error occured: "  + e)
        print("Setting user right for: " + name + " -> " + users)
    print("All user rights assignemnts have been successfully configured")

def func3_start_event_log():
    print("Checking Event Log service status...")
    try:
        # Check if Event Log Service is running
        service_status = subprocess.run(
            ["powershell", "-Command", "Get-Service -Name EventLog | Select-Object -ExpandProperty Status"],
            capture_output=True, text=True, check=True
        ).stdout.strip()

        # Start service if Event Log Service is not running
        if service_status != "Running":
            print("Event Log service is not running. Starting the service...")
            subprocess.run(["powershell", "-Command", "Start-Service -Name EventLog"], check=True)
            print("Event Log service started.")

        # Set Event Log Service to automatically start
        print("Setting Event Log service to start automatically...")
        subprocess.run(["powershell", "-Command", "Set-Service -Name EventLog -StartupType Automatic"], check=True)
        print("Event Log service is now set to start automatically.")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def func4_enable_firewall():
    print("Enabling Windows Firewall for all profiles...")
    try:
        # Enable Windows Firewall for Domain, Private, and Public profiles
        subprocess.run(["powershell", "-Command", "Set-NetFilrewallProfile -Profile Domain,Public,Private -Enabled True"], check=True)
        print("Windows Firewall enabled for all profiles.")
    except subprocess.SubprocessError as e:
        print("Error occured: " + e)

def func5_disable_enable_RDP():
    choice = input("Enable (e) or Disable (d) RDP? (e/d/q): ")
    if choice == "e":
        print("Enabling RDP ...")
        try:
            subprocess.run(["powershell", "-command", 'Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name "fDenyTSConnections" -Value 0'])
            print("RDP has been enabled successfully.")
            print("Starting RDP services ...")
            subprocess.run(["powershell", "-Command", 'Start-Service -Name "TermService"'])
            print("Successfully started RDP services.")
            print("Enabling automatic startup for RDP ...")
            subprocess.run(["powershell", "-Command", 'Set-Service -Name "TermService" -StartupType Automatic'])
            print("Successfully enabled automatic startup for RDP services.")
        except subprocess.SubprocessError as e:
            print("Error occured: " + e)
    elif choice == "d":
        print("Disabling RDP ...")
        try:
            subprocess.run(["powershell", "-Command", 'Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name "fDenyTSConnections" -Value 1;'])
            print("RDP has been disabled successfully.")
            print("Stopping RDP services ...")
            subprocess.run(["powershell", "-Command", 'Stop-Service -Name "TermService" -Force'])
            print("Successfully stopped RDP services.")
            print("Disabling automatic startup for RDP ...")
            subprocess.run(["powershell", 'Set-Service -Name "TermService" -StartupType Disabled'])
            print("Successfully disabled automatic startup for RDP services.")
        except subprocess.SubprocessError as e:
            print("ERror occured: " + e)

def func6_disable_guest_and_admin_accounts():
    print("Disabling the guest account ...")
    try:
        subprocess.run(["powershell", "-Command", 'Disable-LocalUser -Name "Guest"'])
        print("Successfully disabled the guest account.")
    except subprocess.SubprocessError as e:
        print("Error with guest account: " + e)
    print("Disabling the Administrator account ...")
    try:
        subprocess.run(["powershell", "-Command", 'Disable-LocalUser -Name "Administrator"'])
        print("Successfully disabled the Administrator account.")
    except subprocess.SubprocessError as e:
        print("Error with Administrator account: " + e)

main()