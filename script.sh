#!/usr/bin/env bash

# Shut up both commands
function pushd {
	command pushd "$@" > /dev/null || return
}

function popd {
	command popd > /dev/null || return
}

# Repeat a given character
function repl() {
    printf "$1"'%.s' $(eval "echo {1.."$(($2))"}")
}

function get_users() {
    # The <65534 condition is to skip the nobody user
    awk -F: '{if ($3 >= 1000 && $3 < 65534) print $1}' < /etc/passwd
}

# Pattern to match, text, file to check
function edit_or_append() {
    if grep -Eq "$1" "$3"; then
        sed -Ei "s\`$1\`$2\`g" "$3"
    else
        echo "$2" >> "$3"
    fi
}

function prompt_y_n() {
    read -p "$1" response

    case "$response" in
        [yY]*)
            return 0 # true
            ;;
        *)
            return 1 # false
    esac
}

function prompt_y_n_quit() {
    read -p "$1" response

    case "$response" in
        [yY]*)
            return 0 # true
            ;;
        [qQ]*)
            return 2 # secret third option
            ;;
        *)
            return 1 # false
            ;;
    esac
}

# $1 package name
function is_installed() {
    # shellcheck disable=1090
    . <({ derr=$({ dout=$(dpkg -s "$1"); } 2>&1; declare -p dout >&2); declare -p derr; } 2>&1)

    if echo "$derr" | grep -qw "is not installed"; then
        return 1 # false
    else
        return 0 # true
    fi
}

function prompt_install() {
    for package in $1; do
        if ! is_installed "$package"; then
            if prompt_y_n "$package is not installed. Install it now [y/N] "; then
                apt install "$package"
            else
                return 1 # false
            fi
        fi
    done

    return 0 # true
}

function check_perm() {
    echo "Checking $1 permissions"
    perm=$(stat -c '%a' "$1")
    if [ "$perm" != "$2" ]; then
        echo "Unexpected permission $perm for $1 (Expected: $2)"
        if prompt_y_n "Fix permissions [y/N] "; then
            chmod "$2" "$1"
            echo "Changed $1 permissions to $2"
        fi
    fi
}


# $1 the split character
# $2 the regex used by edit_or_append, able to access ::param:: and ::value::
# $3 the path
# $4 the array of parameters
function apply_params_list() {
    local split_char="$1"; shift
    local regex_template="$1"; shift
    local config_file="$1"; shift
    local params=("$@")

    for param_string in "${params[@]}"; do
        IFS="$split_char" read -ra split <<< "$param_string"

        local param="${split[0]}"
        local value="${split[1]}"
        local regex=${regex_template//::param::/$param}
        regex=${regex//::value::/$value}

        echo "Adding $param with value $value to $config_file"
        edit_or_append "$regex" "$param = $value" "$config_file"
    done
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
perms_search_root='/home/'
high_perm_min='700'
high_perm_log='high-perms.log'
world_writeable_log='world-writeable.log'
no_user_log='world-writeable.log'

potentially_bad_software="openssh-server nginx apache caddy postfix sendmail vsftpd smbd lighttpd" # TODO: add more because I keep forgetting
bad_software="aircrack-ng deluge gameconqueror hashcat hydra john nmap openvpn qbittorrent telnet wireguard zenmap ophcrack nc netcat netcat-openbsd nikto wireshark tcpdump netcat-traditional"

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

function update() {
    echo "Running full system upgrade"

    # TODO: I forgot the dist upgrade command, this may need to be edited
    apt update && apt upgrade -y && apt dist-upgrade -y

    echo "Done updating"
}

function auto_update() {
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

function firewall() {
    apt install ufw -y
    ufw default deny
    ufw enable

    echo "Installed and configured ufw"
}

function manage_users() {
    if ! [[ -v admins ]]; then
        echo "No list of users was provided"
        return
    fi

    if ! [[ -v allowed_users ]]; then
        echo "No list of users was provided"
        return
    fi

    users=$(get_users)

    for user in $users; do
        if ! [[ "$allowed_users" == *"$user"* ]] && ! [[ "$admins" == *"$user"* ]]; then
             if prompt_y_n "Unauthorized user $user found, delete the user? [y/N] "; then
                 echo "Deleting user $user"
                 userdel "$user"
             fi
        fi

        # Neat little trick to get both stdout and stderr
        # shellcheck disable=1090,2030
        . <({ gerr=$({ gout=$(groups "$user"); } 2>&1; declare -p gout >&2); declare -p gerr; } 2>&1)

        if [ -n "$gerr" ]; then
            echo "Error '$gerr' when attempting to check groups of $user"
            continue
        fi

        # shellcheck disable=2031
        if echo "$gout" | grep -qw "admin\|wheel\|staff\|sudo\|sudoers"; then
            if ! [[ "$admins" == *"$user"* ]]; then
                if prompt_y_n "User $user appears to be an admin when they should not be, attempt to remove the group? [y/N] "; then
                    # TODO: Maybe don't just try every group??
                    echo "Removing user from groups admin, wheel, staff, sudo, sudoers"
                    gpasswd -d "$user" admin
                    gpasswd -d "$user" wheel
                    gpasswd -d "$user" staff
                    gpasswd -d "$user" sudo
                    gpasswd -d "$user" sudoers
                fi
            fi
        fi
    done

    for user in $admins; do
        # shellcheck disable=1090
        . <({ gerr=$({ gout=$(groups "$user"); } 2>&1; declare -p gout >&2); declare -p gerr; } 2>&1)

        if [ -n "$gerr" ]; then
            echo "Error '$gerr' when attempting to check groups of $user"
            continue
        fi

        if ! echo "$user" | grep -qw "admin\|wheel\|staff\|sudo\|sudoers"; then
            echo "User $user appears not to be an administrator when they should be"
        fi
    done

    echo
    printf "Check for weird admins\n: %s" "$(mawk -F: '$1 == "sudo"' /etc/group) \n"
    printf "Check for weird users\n: %s" "$(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd) \n"
    printf "Check for empty passwords\n: %s" "$(mawk -F: '$2 == ""' /etc/passwd) \n"
    printf "Check for empty passwords\n: %s" "$(mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd) \n"
    echo
    echo "All available users to check against for anything this missed: "
    echo "$users"
    echo

    echo "Done managing users"
}

function change_passwords() {
    echo "$allowed_users"

    for user in $allowed_users; do
        echo "Changing password for $user"
        echo "$user:rnXvDH2iAhiALoNbfdFDiLkfYpt8G3md" | chpasswd
    done

    for user in $admins; do
        if ! [[ "$vm_user" == "$user" ]]; then # WARN: This should probably work. But make sure you know this password just in case
            echo "Changing password for admin $user"
            echo "$user:rnXvDH2iAhiALoNbfdFDiLkfYpt8G3md" | chpasswd
        fi
    done

    echo "Done changing passwords"
}

login_params=(
    "FAILLOG_ENAB=YES"
    "LOG_UNKFAIL_ENAB=YES"
    "SYSLOG_SU_ENAB=YES"
    "SYSLOG_SG_ENAB=YES"
    "PASS_MAX_DAYS=14"
    "PASS_MIN_DAYS=7"
    "PASS_WARN_AGE=7"
)

function expiry() {
    apply_params_list "=" "^::param::\s*=\s*(YES|NO|[0-9]*)" "/etc/login.defs" "${login_params[@]}"

    echo "Finished configuring login.defs"
}

commonpwd_conf="/etc/pam.d/common-password"
commonauth_conf="/etc/pam.d/common-auth"

function setup_cracklib() {
    # TODO: Change to edit or append
    if ! prompt_install "libpam-cracklib"; then
        return
    fi

    echo "Configuring libpam-cracklib"

    if [ ! -f "$commonpwd_conf" ]; then
        echo "$commonpwd_conf is missing"
    else
        sed -i "s/\(pam_unix\.so.*\)$/\1 remember=5 minlen=8/" "$commonpwd_conf"
        sed -i "s/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/" "$commonpwd_conf"
    fi

    if ! [[ -f "$commonauth_conf" ]] || ! grep -qw "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" < "$commonauth_conf"; then
        echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> "$commonauth_conf"
    fi

    echo "Finished confiuring libpam-cracklib"
}

function lock_root() {
    passwd -l root

    echo "Locked root account"
}

function list_media() {
    find "/home/" -type f \( "${media_files[@]}" \) > media_files.log

    echo "Located media files, written to media_files.log"
}

kparams=(
    # Turn on execshield
    "kernel.randomize_va_space=1"

    # IP Spoofing protection
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.default.rp_filter=1"

    # Ignore ICMP broadcast requests
    "net.ipv4.icmp_echo_ignore_broadcasts=1"

    # Disable source packet routing
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv6.conf.all.accept_source_route=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv6.conf.default.accept_source_route=0"

    # Ignore send redirects
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"

    # Block SYN attacks
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.tcp_max_syn_backlog=2048"
    "net.ipv4.tcp_synack_retries=2"
    "net.ipv4.tcp_syn_retries=5"

    # Disable IP packet forwarding
    "net.ipv4.ip_forward=0"

    # Log Martians
    "net.ipv4.conf.all.log_martians=1"
    "net.ipv4.icmp_ignore_bogus_error_responses=1"

    # Ignore ICMP redirects
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"

    # Ignore Directed pings
    "net.ipv4.icmp_echo_ignore_all=1"
)

kp_conf="/etc/sysctl.conf"

function kernel_parameters() {
    if [ ! -f "$kp_conf" ]; then
        if prompt_y_n "$kp_conf does not exist, create it now? [y/N] "; then
            touch "$kp_conf"
        else
            return
        fi
    fi

    apply_params_list "=" "^::param::\s*=\s*[0-9]*" "$kp_conf" "${kparams[@]}"

    echo "Validating changes to sysctl.conf"

    sysctl_out=$(sysctl -p)

    for param_string in "${kparams[@]}"; do
        IFS="=" read -ra split <<< "$param_string"

        local param="${split[0]}"
        local value="${split[1]}"

        if [[ "$sysctl_out" != *"$param = $value"* ]]; then
            echo "parameter $param was not successfully set to $value"
        fi
    done

    echo "Finished checking kernel parameters in $kp_conf"
}

function remove_software() {
    apt purge "$bad_software"

    echo "Removed disallowed software"
}

function unwanted_programs() {
    for program in $potentially_bad_software; do
        if is_installed "$program"; then
            echo "Potentially unwanted program $program is installed, consider removing it if it should not be there"
        fi
    done

    echo "Finished checking for unwanted programs"
}

function password_files() {
    if ! prompt_install "ripgrep"; then
        return
    fi

    if [[ -f patterns ]]; then
        rm patterns
    fi

    for password in $passwords; do
        echo "$password" >> patterns
    done

    echo "Checking for files containing passwords"
    # TODO: Any way to speed this up?
    printf "Files containing passwords located in: \n%s" "$(rg --hidden --no-ignore --files-with-matches --fixed-strings -f patterns /home/)"
}

function list_units() {
    echo "Check enabled units for anything unwanted"
    systemctl list-units --type=service --state=active
    echo
}

# Hoping there aren't more or else they'll lose exec permissions...
files_needing_exec=(
    ".profile"
    ".bashrc"
    ".bash_logout"
)

function verify_perms() {
    check_perm /etc/passwd 644 false
    check_perm /etc/group 644 false
    check_perm /etc/shadow 0 false

    # Fix home directory permissions
    echo "Checking home directory permissions"
    for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do
        if [ ! -d "/home/${i}" ]; then
            echo "No home directory for user $i"
            continue;
        else
            echo "Fixing permissions for directory /home/$i"
        fi

        # output to temp file because looping through find output is a pain in the ass otherwise...
        find "/home/${i}" > tmphomefiles

        while IFS= read -r file; do
            if [ -d "$file" ] || [[ "${files_needing_exec[*]}" == *$(basename "$file")* ]]; then
                chmod 700 "$file"
            elif [ -f "$file" ]; then
                chmod 600 "$file"
            fi
        done < tmphomefiles

        if [ -f tmphomefiles ]; then
            rm tmphomefiles
        fi
    done

    find "$perms_search_root" -type f -perm "-$high_perm_min" > "$high_perm_log"
    echo "Found $(wc -l < "$high_perm_log") files with permissions 700 or higher in $perms_search_root!"

    find "$perms_search_root" -xdev -type d \( -perm -0002 -a ! -perm -1000 \) > "$world_writeable_log"
    echo "Found $(wc -l < "$high_perm_log") files with permissions 700 or higher in $perms_search_root!"

    find "$perms_search_root" -xdev \( -nouser -o -nogroup \) > "$no_user_log"
    echo "Found $(wc -l < "$high_perm_log") files with permissions 700 or higher in $perms_search_root!"
}

function check_rc_local() {
    if [[ -f /etc/rc.local ]]; then
        echo "/etc/rc.local exists, check for anything unwanted"
        cat /etc/rc.local
    else
        echo "/etc/rc.local does not exist"
    fi
}

function disable_hardware() {
    echo "Disabling usb-storage, firewire, and thunderbolt"

    echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf
    echo "blacklist firewire-core" > /etc/modprobe.d/firewire.conf
    echo "blacklist thunderbolt" > /etc/modprobe.d/thunderbolt.conf

    echo "Disabled hardware"
}

shopt -s nullglob
cronfiles=(
    /etc/cron.*/*
    /etc/crontab
    /var/spool/cron/crontabs/*
    /etc/init/*
    /etc/init.d/*
)
shopt -u nullglob

function check_crontabs() {
    for file in "${cronfiles[@]}"; do
        prompt_y_n_quit "View contents of $file [y/N/q] "
        response=$?
        if [ $response -eq 0 ]; then
            less < "$file"
        elif [ $response -eq 2 ]; then
            break
        fi
    done

    users=$(get_users)

    for user in $users; do
        prompt_y_n_quit "View contents of crontab for $user [y/N/q] "
        response=$?
        if [ $response -eq 0 ]; then
            crontab -u "$user" -l
        elif [ $response -eq 2 ]; then
            break
        fi
    done
}

function rkhunter() {
    if ! prompt_install "rkhunter"; then
        return
    fi

    rkhunter --update
    rkhunter -c --sk
}

function clamav() {
    if ! prompt_install "clamav clamtk"; then
        return
    fi

    if prompt_y_n "Enable freshlclam service [y/N] "; then
        systemctl enable --now clamav-freshclam
    fi

    clamscan / --log --recursive -- verbose
}

lightdm_conf="/etc/lightdm/lightdm.conf"

# Not sure if these parameters will work

lightdm_params=(
    "greeter-allow-guest=false"
    "greeter-hide-users=true"
    "greeter-show-manual-login=true"
    "autologin-user=none"
    "allow-guest=false"
)

gdm3_conf="/etc/gdm3/greeter.dconf-defaults"
gdm3_params=(
    "disable-user-list=true"
    "disable-restart-buttons=true"
)

gdm3_custom_conf="/etc/gdm3/custom.conf"
gdm3_custom_params=(
    "AutomaticLoginEnable=false"
)

function display_manager() {
    if [ -f "$lightdm_conf" ]; then
        echo "Fixing $lightdm_conf settings"
        apply_params_list "=" "^::param::\s*=\s*true|false" "$lightdm_conf" "${lightdm_params[@]}"
    fi

    if [ -f "$gdm3_conf" ]; then
        echo "Fixing $gdm3_conf settings"
        apply_params_list "=" "^::param::\s*=\s*true|false" "$gdm3_conf" "${gdm3_params[@]}"
    fi

    if [ -f "$gdm3_custom_conf" ]; then
        echo "Fixing $gdm3_custom_conf settings"
        apply_params_list "=" "^::param::\s*=\s*true|false" "$gdm3_custom_conf" "${gdm3_custom_params[@]}"
    fi
}

function auditd() {
    if ! prompt_install "auditd"; then
        return
    fi

    auditctl -e 1

    echo "Enabled auditd"
}

# $1 the original file
# #2 the filename only
# $3 the xxh64sum
# $4 the user to operate on
function diff_default_files_inner() {
    # WARN: This might be a little overengineered. Oh well. Probably shouldn't be changing directories
    pushd "/home/$4" || return

    newsum=$(xxh64sum "$2")

    if [ ! "$newsum" = "$3" ]; then
        if prompt_y_n "The hash of /home/$user/$2 does not match the stored hash, view diff? [y/N] "; then
            diff -u --color=always -- "$1" "/home/$user/$2" | less -R
        fi
    fi

    # If it fails to return to the dir something has gone terribly wrong.
    popd || exit 1
}

function diff_default_files() {
    shopt -s dotglob

    # These files contain default, safe configurations and their hashes with user home local paths
    if [ ! -d "./default_files/" ]; then
        echo "Missing default_files directory. Please get them from the repo before continuing"
        return
    fi

    for file in ./default_files/*; do
        if [[ "$file" == *.hash ]]; then
            continue
        fi

        sum=$(cat "$file.hash")
        rel_path=${file#*/}
        rel_path=${rel_path#*/}

        users=$(get_users)

        for user in $users; do
            if [ ! -f "/home/$user/$rel_path" ]; then
                continue
            fi

            echo "Checking $rel_path for user $user"
            diff_default_files_inner "$(realpath "$file")" "$rel_path" "$sum" "$user"
        done

    done

    shopt -u dotglob
}

function enable_se_linux() {
    if ! prompt_install "selinux-utils selinux-basics"; then
        return
    fi

    selinux-activate
    selinux-config-enforcing

    echo "Enabled selinux"
}

function print_help() {
    echo \
"
ppeb's cyber patriot linux script!!!

Usage: script.sh [OPTIONS]
 --users                       Comma/semicolon separated list of your user, administrators, normal users, and passwords: {your user;admin1,admin2,admin3;normal1,normal2,normal3;password1,password2}. Note that if the password contains commas you're fucked
 --readme                      Link to grab readme from; will be parsed for authorized users and administrators
"
}
# TODO: Should add smb, ssh, vsftp, apache, and more secure configurations eventually

# SCRIPT BEGINS HERE!!!!!!

user=$(whoami)

if [ "$user" != 'root' ]; then
    echo 'Please run this as root!'
    echo "Current user: $user"
    exit 1
fi

if [ $# -eq 0 ]; then # Check for commands
    echo "No users or readme supplied"
    print_help
    exit 1
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_help
            exit
        ;;
        --users)
            ;;
        --readme)
            file=$(echo -n "$2" | md5sum | awk '{print $1}')
            file="$file.urlhash"

            # Hash the url and write it to a file so repeated requests aren't made
            if [ ! -e "$file" ]; then
                text=$(curl "$2")
                echo "$text" > "$file"
            else
                text=$(cat "$file")
            fi

            # PRAYING THIS WORKS OR I'LL KILL MYSELF
            if [[ $text =~ $readme_exp ]]; then
                admins="${BASH_REMATCH[1]}"
                allowed_users="${BASH_REMATCH[2]}" # DOES NOT INCLUDE ADMINS
                admins=${admins#*$'\n'}
                # There should no longer be random newlines here
                passwords=$(echo "$admins" | grep "password" | sed "s/password: //g" | sed "s/^[ \t]*//" )
                admins=$(echo "$admins" | grep -v "password" | sed "s/(you)//g" | tr -d "\r")
                vm_user=$(echo "$admins" | head -n1  | tr -cd "[:alnum:]._-")
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

funcs=(
    update
    auto_update
    firewall
    manage_users
    change_passwords
    expiry
    setup_cracklib
    lock_root
    list_media
    kernel_parameters
    remove_software
    unwanted_programs
    password_files
    list_units
    verify_perms
    check_rc_local
    disable_hardware
    check_crontabs
    rkhunter
    clamav
    display_manager
    auditd
    diff_default_files
    enable_se_linux
)

re='^[0-9]+$'
function menu() {
    echo

    # Spacing is a little off once it gets to 2 digits but I don't care. Someone else can fix it
    for ((i = 0; i < ${#funcs[@]}; i += 2)); do
        prefix="($i)"
        line="$prefix ${funcs[i]}"
        if [ -n "${funcs[i + 1]}" ]; then
            line="$line$(repl ' ' $(( 25 - (${#funcs[i]} + ${#prefix}) )))($((i + 1))) ${funcs[i + 1]}"
        fi
        echo "$line"
    done
    read -r -p '> ' input

    if ! [[ $input =~ $re ]] ; then
       echo "Please enter a number."
       return
    fi

    if [[ $input -ge "${#funcs[@]}" ]] || [[ $input -lt 0 ]]; then
        echo "Please enter a number from 0 to $(( ${#funcs[@]} - 1 ))"
        return
    fi

    echo
    ${funcs[$input]}
}

echo "ppeb's cybsec script. warranty not included, use at your own risk"
while true; do menu; done
