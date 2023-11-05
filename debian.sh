#!/usr/bin/env bash

function get_users {
    # The <65534 condition is to skip the nobody user
    users=$(awk -F: '{if ($3 >= 1000 && $3 < 65534) print $1}' < /etc/passwd)
}

# Pattern to match, text, file to check
function edit_or_append {
    if grep -Eq "$1" "$3"; then
        sed -Ei "s\`$1\`$2\`g" "$3"
    else
        echo "$2" >> "$3"
    fi
}

function prompt_y_n {
    read -p "$1" response

    case "$response" in
        [yY]*)
            return 1
            ;;
        *)
            return 0
    esac
}

function check_perm {
    echo "Checking $1 permissions"
    perm=$(stat -c '%a' "$1")
    if [ "$perm" != "$2" ]; then
        echo "Unexpected permission $perm for $1 (Expected: $2)"
        if [ "$3" = 1 ]; then
            chmod "$2" "$1"
            echo "Changed $1 permissions to $2"
        fi
    fi
}

# Password expiry settings
pass_max_exp='^PASS_MAX_DAYS\s+[0-9]+'
pass_min_exp='^PASS_MIN_DAYS\s+[0-9]+'
pass_warn_exp='^PASS_WARN_AGE\s+[0-9]+'

# sshd settings
ssh_root_exp='^PermitRootLogin\s+(yes|no)'
ssh_empty_pass_exp='^PermitEmptyPasswords\s+(yes|no)'

# APT settings
apt_check_interval_exp='^APT::Periodic::Update-Package-Lists\s+"[0-9]+";'
apt_download_upgradeable_exp='^APT::Periodic::Download-Upgradeable-Packages\s+"[0-9]+";'
apt_autoclean_interval_exp='^APT::Periodic::AutocleanInterval\s+"[0-9]+";'
apt_unattended_exp='^APT::Periodic::Unattended-Upgrade\s+"[0-9]+";'

readme_exp="Authorized Administrators:(.*?)<b>Authorized Users:<\/b>(.*?)<\/pre>"

# Config file locations
sshd_conf='/etc/ssh/sshd_config'
apt_periodic_conf='/etc/apt/apt.conf.d/10periodic'
apt_autoupgrade_conf='/etc/apt/apt.conf.d/20auto-upgrades'

# Password expiry settings
pass_max='14'
pass_min='7'
pass_warn='7'

# Permissive file search parameters
high_perm_min='700'
high_perm_file='high-perms.log'
high_perm_root='/home/'

potentially_bad_software="openssh-server nginx apache caddy postfix sendmail vsftpd smbd" # TODO: add more because I keep forgetting
bad_software='aircrack-ng deluge gameconqueror hashcat hydra john nmap openvpn qbittorrent telnet wireguard zenmap ophcrack nc netcat netcat-openbsd'

media_files_raw=(
    # Audio formats
    'aa'
    'aac'
    'aax'
    'act'
    'aif'
    'aiff'
    'alac'
    'amr'
    'ape'
    'au'
    'awb'
    'dss'
    'dvf'
    'flac'
    'gsm'
    'iklax'
    'ivs'
    'm4a'
    'm4b'
    'mmf'
    'mp3'
    'mpc'
    'msv'
    'nmf'
    'ogg'
    'oga'
    'mogg'
    'opus'
    'ra'
    'raw'
    'rf64'
    'sln'
    'tta'
    'voc'
    'vox'
    'wav'
    'wma'
    'wv'
    '8svx'
    'cda'
    # Video formats
    'webm'
    'mkv'
    'flv'
    'vob'
    'ogv'
    'ogg'
    'drc'
    'gif'
    'gifv'
    'mng'
    'avi'
    'mts'
    'm2ts'
    'mov'
    'qt'
    'wmv'
    'yuv'
    'rm'
    'rmvb'
    'viv'
    'asf'
    'amv'
    'mp4'
    'm4p'
    'm4v'
    'mpg'
    'mp2'
    'mpeg'
    'mpe'
    'mpv'
    'm2v'
    'svi'
    '3gp'
    '3g2'
    'mxf'
    'roq'
    'nsv'
    'f4v'
    'f4p'
    'f4a'
    'f4b'
    # Picture formats
    'png'
    'jpg'
    'jpeg'
    'jfif'
    'exif'
    'tif'
    'tiff'
    'gif'
    'bmp'
    'ppm'
    'pgm'
    'pbm'
    'pnm'
    'webp'
    'heif'
    'avif'
    'ico'
    'tga'
    'psd'
    'xcf'
)

# TODO: Who the fuck wrote this I need to edit it

media_files=()

# Convert list of extensions to parameters for find command
for extension in "${media_files_raw[@]}"; do
    if [ $media_files ]; then media_files+=('-o'); fi
    media_files+=('-iname')
    media_files+=("*.$extension")
done

function update {
    echo "Running full system upgrade"

    # TODO: I forgot the dist upgrade command, this may need to be edited
    apt update && apt upgrade -y && apt dist-upgrade -y

    echo "Done updating"
}

function auto_update {
    edit_or_append "$apt_check_interval_exp" 'APT::Periodic::Update-Package-Lists "1";' "$apt_periodic_conf"
    echo "Enabled daily update checks"

    edit_or_append "$apt_download_upgradeable_exp" 'APT::Periodic::Download-Upgradeable-Packages "1";' "$apt_periodic_conf"
    echo "Enabled auto-downloading upgradeable packages"

    edit_or_append "$apt_autoclean_interval_exp" 'APT::Periodic::AutocleanInterval "7";' "$apt_periodic_conf"
    echo "Enabled weekly autoclean"

    edit_or_append "$apt_unattended_exp" 'APT::Periodic::Unattended-Upgrade "1";' "$apt_periodic_conf"
    echo "Enabled unattended upgrades"

    cp -f "$apt_periodic_conf" "$apt_autoupgrade_conf"

    echo "Done configuring automatic updates!"
}

function firewall {
    apt install ufw -y
    ufw default deny
    ufw enable

    echo "Installed and configured ufw"
}

function manage_users {
    # WARN: I have literally no clue if any of this works lmfao
    if ! [[ -v admins ]]; then
        echo "No list of users was provided"
    fi

    if ! [[ -v allowed_users ]]; then
        echo "No list of users was provided"
    fi

    get_users

    for user in $users; do
        if ! [[ "$allowed_users" == *"$user"* ]]; then
             if prompt_y_n "Unauthorized user $user found, delete the user? [y/N]"; then
                 userdel "$user"
                 continue
             fi

        fi

        if groups "$user" | grep -qw "admin\|wheel\|staff\|sudo\|sudoers"; then
            if ! [[ "$admins" == *"$user"* ]]; then
                if prompt_y_n "User $user appears to be an admin when they should not be, remove the group? [y/N]"; then
                    # TODO: Maybe don't just try every group??
                    gpasswd -d "$user" admin
                    gpasswd -d "$user" wheel
                    gpasswd -d "$user" statff
                    gpasswd -d "$user" sudo
                    gpasswd -d "$user" sudoers
                fi
            fi
        fi
    done

    for user in $admins; do
        if ! groups "$user" | grep -qw "admin\|wheel\|staff\|sudo\|sudoers"; then
            echo "User $user appears not to be an administrator when they should be"
        fi
    done

    echo "All available users to check against for anything this missed"
    echo "$users"

    echo "Done managing users"
}

function passwords {
    for user in $allowed_users; do
        echo "Changing password for $user"
        echo "$user:rnXvDH2iAhiALoNbfdFDiLkfYpt8G3md" | chpasswd
    done

    for user in $admins; do
        if ! [[ "$vm_user" == "$user" ]]; then # WARN: CHECK THIS BEFORE RUNNING BECAUSE I DON'T WANNA LOCK MYSELF OUT
            echo "changing password for $user"
            # echo "$user:rnXvDH2iAhiALoNbfdFDiLkfYpt8G3md" | chpasswd
        fi
    done

    echo "Done changing passwords"
}

function expiry {
    edit_or_append "$pass_max_exp" "PASS_MAX_DAYS	$pass_max" '/etc/login.defs'
    echo 'Set max age'

    edit_or_append "$pass_min_exp" "PASS_MIN_DAYS	$pass_min" '/etc/login.defs'
    echo 'Set minimum age'

    edit_or_append "$pass_warn_exp" "PASS_WARN_AGE	$pass_warn" '/etc/login.defs'
    echo 'Set age warning'
}

function lock_root {
    passwd -l root

    echo "Locked root account"
}

function list_media {
    find "/home/" -type f \( "${media_files[@]}" \) > media_files.log

    echo "Located media files, written to media_files.log"
}

function kernel_parameters {
    echo "Unimplemented because I ran out of time to figure out the params lol"
}

function remove_software {
    apt purge "$bad_software"

    echo "Removed disallowed software"
}

function unwanted_programs {
    installed=$(apt list --installed)
    for program in $potentially_bad_software; do
        if echo "$installed" | grep -qw "$program"; then
            echo "Potentially unwanted program $program is installed, consider removing it if it should not be there"
        fi
    done
}

function password_files {
    if ! command -v rg &> /dev/null; then
        apt install ripgrep
    fi

    if [[ -f patterns ]]; then
        rm patterns
    fi

    for password in $passwords; do
        echo "$password" >> patterns
    done

    echo "Checking for files containing passwords"
    # TODO: Any way to speed this up?
    printf "Files containing passwords located in: $(rg --hidden --no-ignore --files-with-matches --fixed-strings -f patterns /home/)"
}

function extras {
    echo "Check enabled units for anything unwanted"
    systemctl list-units --type=service --state=active

    if [[ -f /etc/rc.local ]]; then
        echo "/etc/rc.local exists, check for anything unwanted"
        cat /etc/rc.local
    fi

    check_perm /etc/passwd 644 true
    check_perm /etc/group 644 true
    check_perm /etc/shadow 0 true

    find "$high_perm_root" -type f -perm "-$high_perm_min" > "$high_perm_file"
    echo "Found $(wc -l < "$high_perm_file") files with permissions 700 or higher in $high_perm_root!"
}

function print_help {
    echo \
"
ppeb's cyber patriot linux script!!!

Usage: script.sh [OPTIONS]

Options:
 -u|--update                   Runs debian update commands
 -au|--auto-updates            Enables automatic updates
 -f|--firewall                 Installs, enables, and configures ufw
 -mu|--manage-users            Deletes unathorized users, ensures all admins are correct, either from a list passed in by --users or from a parsed readme link in --readme
 -pw|--passwords               Set all passwords (except for your account) to a given string
 -e|--expiry                   Configure password expiry in /etc/login.defs. May want to use cracklib or other pam settings eventually
 -lr|--lock-root               Locks the root account
 -lm|--list-media              Lists media files
 -kp|--kernel-parameters       Configures kernel parameters in the file
 -rs|--remove-software         Removes disallowed software
 -pup|--unwanted-programs      Lists potentially unwanted programs that are installed
 -pwf|--password-files         Search for any passwords (from the readme) stored in files
 -ex|--extras                  A couple little checks that could be useful
 --all                         Runs everything prior. Needs --readme or --users

These options apply globally or to multiple commands:
 --users                       Comma/semicolon separated list of your user, administrators, normal users, and passwords: {your user;admin1,admin2,admin3;normal1,normal2,normal3;password1,password2}. Note that if the password contains commas you're fucked
 --readme                      Link to grab readme from; will be parsed for authorized users and administrators
"
}
# TODO: Adding clamscan and rkhunter (and enabling them) may be worth something. Give it a shot manually for now bc I'm too lazy to make it configure shit. Should add smb, ssh, vsftp, apache, and more secure configurations eventually

# SCRIPT BEGINS HERE!!!!!!

user=$(whoami)

if [ "$user" != 'root' ]; then
    echo 'Please run this as root!'
    echo "Current user: $user"
    exit 1
fi

if [ $# -eq 0 ]; then # Check for commands
    echo "No command supplied"
    print_help
    exit 1
fi

# We love the fatass switch case
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_help
            exit
        ;;
        -u|--update)
            r_update=true
            shift
            ;;
        -au|--auto-updates)
            r_auto_updates=true
            shift
            ;;
        -f|--firewall)
            r_firewall=true
            shift
            ;;
        -mu|--manage-users)
            r_mu=true
            shift
            ;;
        -pw|--passwords)
            r_pw=true
            shift
            ;;
        -e|--expiry)
            r_e=true
            shift
            ;;
        -lr|--lock-root)
            r_lr=true
            shift
            ;;
        -lm|--list-media)
            r_lm=true
            shift
            ;;
        -kp|--kernel-parameters)
            r_kp=true
            shift
            ;;
        -rs|--remove-software)
            r_rs=true
            shift
            ;;
        -pup|--unwanted-programs)
            r_pup=true
            shift
            ;;
        -pwf|--password-files)
            r_pwf=true
            shift
            ;;
        -ex|--extras)
            r_ex=true
            shift
            ;;
        --all)
            all=true
            shift
            ;;
        --users)
            ;;
        --readme)
            link="$2"
            text=$(curl "$link")

            # PRAYING THIS WORKS OR I'LL KILL MYSELF
            if [[ $text =~ $readme_exp ]]; then
                admins="${BASH_REMATCH[1]}"
                allowed_users="${BASH_REMATCH[2]}"
                admins=${admins#*$'\n'}
                passwords=$(echo "$admins" | grep "password" | sed "s/password: //g" | sed "s/^[ \t]*//" )
                admins=$(echo "$admins" | grep -v "password" | sed "s/(you)//g")
                vm_user=$(echo "$admins" | head -n1)
            fi

            shift
            shift
            ;;
        *)
            echo "Unknown argument $1"
            print_help
            exit
            ;;
    esac
done

if [[ -v all ]]; then
    if ! [[ -v admins ]] || ! [[ -v allowed_users ]] || ! [[ -v passwords ]] || ! [[ -v vm_user ]]; then
        echo "Please use --readme when using --all"
        exit
    fi
fi

# This is all annoying as hell but like I needed to parse options before running anything so this is the easiest option to do at 3 am
if [[ -v r_update ]] || [[ -v all ]]; then
    update
fi

if [[ -v r_auto_updates ]] || [[ -v all ]]; then
    auto_update
fi

if [[ -v r_firewall ]] || [[ -v all ]]; then
    firewall
fi

if [[ -v r_mu ]] || [[ -v all ]]; then
    manage_users
fi

if [[ -v r_pw ]] || [[ -v all ]]; then
    passwords
fi

if [[ -v r_e ]] || [[ -v all ]]; then
    expiry
fi

if [[ -v r_lr ]] || [[ -v all ]]; then
    lock_root
fi

if [[ -v r_lm ]] || [[ -v all ]]; then
    list_media
fi

if [[ -v r_kp ]] || [[ -v all ]]; then
    kernel_parameters
fi

if [[ -v r_rs ]] || [[ -v all ]]; then
    remove_software
fi

if [[ -v r_pup ]] || [[ -v all ]]; then
    unwanted_programs
fi

if [[ -v r_pwf ]] || [[ -v all ]]; then
    password_files
fi

if [[ -v r_ex ]] || [[ -v all ]]; then
    extras
fi
