import pywin32_system32
import winreg as reg
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
        1) Enable auto updates                 10) Test
        2) Configure User Rights Assignments   
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
        "Access Credential Manager as a trusted caller": "No one",
        "Access the computer from the network": "Administrators",
        "Act as part of the operating system": "No one",
        "Adjust memory quotas for a process": "Administrators, LOCAL SERVICE, NETWORK SERVICE",
        "Allow log on locally": "Administrators, Users",
        "Allow log on through Remote Desktop Services": "Administrators, Remote Desktop Users",
        "Back up files and directories": "Administrators",
        "Change system time": "Administrators, LOCAL SERVICE",
        "Change the time zone": "Administrators, LOCAL SERVICE, Users",
        "Create a pagefile": "Administrators",
        "Create a token object": "No one",
        "Create global objects": "Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE",
        "Create permanent shared objects": "No one",
        "Create symbolic links": "Administrators",
        "Debug programs": "Administrators",
        "Deny access to this computer from the network": "Guest, Local account",
        "Deny log on as a batch job": "Guest",
        "Deny log on as a service": "Guest",
        "Deny log on locally": "Guest",
        "Deny log on through Remote Desktop Services": "Guest, Local account",
        "Enable computer and user accounts to be trusted for delegation": "No one",
        "Force shutdown from a remote system": "Administrators",
        "Generate security audits": "LOCAL SERVICE, NETWORK SERVICE",
        "Impersonate a client after authentication": "Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE",
        "Increase scheduling priority": "Administrators",
        "Load and unload device drivers": "Administrators",
        "Lock pages in memory": "No one",
        "Log on as a batch job": "Administrators",
        "Log on as a service": "No one",
        "Manage auditing and security log": "Administrators",
        "Modify an object label": "No one",
        "Modify firmware environment values": "Administrators",
        "Perform volume maintenance tasks": "Administrators",
        "Profile single process": "Administrators",
        "Profile system performance": "Administrators, NT SERVICE\\WdiServiceHost",
        "Replace a process level token": "LOCAL SERVICE, NETWORK SERVICE",
        "Restore files and directories": "Administrators",
        "Shutdown the system": "Administrators, Users",
        "Take ownership of file or other objects": "Administrators"
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

main()