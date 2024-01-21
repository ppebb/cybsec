#!/usr/bin/env bash

# Exit if something errors to avoid something going terribly wrong...
set -e

source ./utils.sh

perms_search_root="/home/"
high_perm_min="700"
high_perm_log="$log_base/high-perms.log"
world_writeable_log="$log_base/world-writeable.log"
world_readable_log="$log_base/world_readable.log"
no_user_log="$log_base/world-writeable.log"
setuid_gid_log="$log_base/setuid_gid.log"
media_files_log="$log_base/media_files.log"
downloaded_packages_log="$log_base/downloaded_packages.log"

function update() {
    echo "Running full system upgrade"

    if [ -n "$(apt-mark showhold)" ]; then
        echo "Some packages were held back. Unholding"
        apt-mark unhold "*"
    fi

    apt update && apt upgrade -y && apt dist-upgrade -y

    echo "Done updating"
}

# APT settings
apt_periodic_conf="/etc/apt/apt.conf.d/10periodic"
apt_autoupgrade_conf="/etc/apt/apt.conf.d/20auto-upgrades"
apt_settings=(
    "APT::Periodic::Update-Package-Lists \"1\";"
    "APT::Periodic::Download-Upgradeable-Packages \"1\";"
    "APT::Periodic::AutocleanInterval \"7\";"
    "APT::Periodic::Unattended-Upgrade \"1\";"
)

function auto_update() {
    apply_params_list " " "^::param::\s*\"[0-9]" "$apt_periodic_conf" "${apt_settings[@]}"

    cp -f "$apt_periodic_conf" "$apt_autoupgrade_conf"

    echo "Done configuring automatic updates!"
}

function firewall() {
    apt install ufw -y
    ufw default deny
    ufw enable

    echo "Installed and configured ufw"
}

admin_groups=(
    "admin"
    "wheel"
    "staff"
    "sudo"
    "adm"
    "lpadmin"
)

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
        if ! user_exists "$user"; then
            echo "Attempted to check user '$user', but they do not exist"
            continue
        fi

        if ! [[ "$allowed_users" == *"$user"* ]] && ! [[ "$admins" == *"$user"* ]]; then
             if prompt_y_n "Unauthorized user '$user' found, delete the user? [y/N] "; then
                 echo "Deleting user '$user'"
                 userdel "$user"
                 continue
             fi
        fi

        # Neat little trick to get both stdout and stderr
        # shellcheck disable=1090,2030
        . <({ gerr=$({ gout=$(groups "$user"); } 2>&1; declare -p gout >&2); declare -p gerr; } 2>&1)

        if [ -n "$gerr" ]; then
            echo "Error '$gerr' when attempting to check groups of $user"
            continue
        fi

        for group in "${admin_groups[@]}"; do
            # shellcheck disable=2031
            if echo "$gout" | grep -qw "$group" && ! [[ "$admins" == *"$user"* ]]; then
                if prompt_y_n "User $user is part of group $group when they should not be. Remove them from the group? [y/N]"; then
                    echo "Removing $user from $group"
                    gpasswd -d "$user" "$group"
                fi
            fi
        done
    done

    for user in $admins; do
        # Don't need to check user_exists. This should catch everything I hope
        # shellcheck disable=1090
        . <({ gerr=$({ gout=$(groups "$user"); } 2>&1; declare -p gout >&2); declare -p gerr; } 2>&1)

        if [ -n "$gerr" ]; then
            echo "Error '$gerr' when attempting to check groups of $user"
            continue
        fi

        if ! echo "$user" | grep -qw "admin\|wheel\|staff\|sudo\|sudoers\|adm\|lpadm"; then
            echo "User $user appears not to be an administrator when they should be"
        fi
    done

    echo
    printf "Check for weird admins:\n %s \n" "$(mawk -F: '$1 == "sudo"' /etc/group) \n"
    printf "Check for weird users:\n %s \n" "$(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd) \n"
    printf "Check for empty passwords:\n %s \n" "$(mawk -F: '$2 == ""' /etc/passwd) \n"
    printf "Check for empty passwords:\n %s \n" "$(mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd) \n"

    echo "Done managing users"
}

function change_passwords() {
    for user in $allowed_users; do
        if ! user_exists "$user"; then
            echo "Attempted to check user '$user', but they do not exist"
            continue
        fi

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
    apply_params_list "=" "^::param::\s*=\s*YES|NO|[0-9]*" "/etc/login.defs" "${login_params[@]}"

    echo "Finished configuring login.defs"
}

commonpwd_conf="/etc/pam.d/common-password"
commonauth_conf="/etc/pam.d/common-auth"

# WARN: This fucking breaks on ubuntu 22 AND debian 11 for some reason. I don't know if it's because of pwquality conflicting with cracklib or because I fucked up a setting. Kill me.
# TODO: Setup pwquality. Figure out what a gdm "correctly configured authentication stack"
# TODO: What the fuck is a GECOS field. GECOS pw strength checks
# TODO: Apparently invididual users can have a minimum password age? Maybe figure out how to reset the time data of user passwords. I think reassigning every user a new password should do it...
function setup_cracklib() {
    if ! prompt_install "libpam-cracklib"; then
        return
    fi

    echo "Configuring libpam-cracklib"

    echo "Backing up config in case something goes wrong"
    cp "$commonpwd_conf" "$commonpwd_conf.bak"
    cp "$commonauth_conf" "$commonauth_conf.bak"

    if [ ! -f "$commonpwd_conf" ]; then
        echo "$commonpwd_conf is missing"
    else
        sed -i "s/\(pam_unix\.so.*\)$/\1 remember=5 minlen=8/" "$commonpwd_conf"
        sed -i "s/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/" "$commonpwd_conf"
        sed -i "s/nullok_secure//" "$commonpwd_conf"
        sed -i "s/yescrypt/sha512crypt/g" "$commonpwd_conf"
    fi

    if ! [[ -f "$commonauth_conf" ]] || ! grep -qw "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" < "$commonauth_conf"; then
        echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> "$commonauth_conf"
    fi

    # Remove null passwords
    if [[ -f "$commonauth_conf" ]]; then
        sed -i "s/nullok//" "$commonauth_conf"
    fi

    echo "Finished confiuring libpam-cracklib"
}

function lock_root() {
    passwd -l root

    echo "Locked root account"
}

media_files_raw=( "aa" "aac" "aax" "act" "aif" "aiff" "alac" "amr" "ape" "au" "awb" "dss" "dvf" "flac" "gsm" "iklax" "ivs" "m4a" "m4b" "mmf" "mp3" "mpc" "msv" "nmf" "ogg" "oga" "mogg" "opus" "ra" "raw" "rf64" "sln" "tta" "voc" "vox" "wav" "wma" "wv" "8svx" "cda" "webm" "mkv" "flv" "vob" "ogv" "ogg" "drc" "gif" "gifv" "mng" "avi" "mts" "m2ts" "mov" "qt" "wmv" "yuv" "rm" "rmvb" "viv" "asf" "amv" "mp4" "m4p" "m4v" "mpg" "mp2" "mpeg" "mpe" "mpv" "m2v" "svi" "3gp" "3g2" "mxf" "roq" 'nsv' "f4v" "f4p" "f4a" "f4b" "png" "jpg" "jpeg" "jfif" "exif" "tif" "tiff" "gif" "bmp" "ppm" "pgm" "pbm" "pnm" "webp" "heif" "avif" "ico" "tga" "psd" "xcf" )

# TODO: Who the fuck wrote this I need to edit it
media_files=()

# Convert list of extensions to parameters for find command
for extension in "${media_files_raw[@]}"; do
    if [ $media_files ]; then media_files+=('-o'); fi
    media_files+=('-iname')
    media_files+=("*.$extension")
done

function list_disallowed_files() {
    find "/home/" -type f \( "${media_files[@]}" \) > "$media_files_log"

    find "/home/" -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \) > "$downloaded_packages_log"

    echo "Located media files and downloaded packages, written to logs"
}

kparams=(
    "kernel.randomize_va_space=1"

    # Block dmesg access from unprivileged users
    "kernel.dmesg_restrict=1"

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

    # IPv4 TIME-WAIT assassination protection
    # "net.ipv4.tcp_ref1337=1" # This doesn't work

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

bad_software_list=("aircrack-ng" "deluge" "gameconqueror" "hashcat" "hydra" "john" "john-data" "nmap" "openvpn" "qbittorrent" "telnet" "wireguard" "zenmap" "ophcrack" "nc" "netcat" "netcat-openbsd" "nikto" "wireshark" "tcpdump" "netcat-traditional" "minetest")

function bad_software() {
    apt purge "${bad_software_list[*]}"

    echo "Removed disallowed software"
}

potentially_unwanted_software=("openssh-server" "nginx" "apache" "caddy" "postfix" "sendmail" "vsftpd" "smbd" "lighttpd") # TODO: add more because I keep forgetting

function unwanted_programs() {
    for program in "${potentially_unwanted_software[@]}"; do
        if is_installed "$program"; then
            echo "Potentially unwanted program $program is installed, consider removing it if it is not a critical service"
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
    printf "Files containing passwords located in: \n%s" "$(rg --hidden --no-ignore --files-with-matches --fixed-strings -f patterns /home/)"
}

# This isn't even close to comprehensive. Should add more probably (definitely)
potentially_unwanted_units=(
    "nginx.service"
    "apache.service"
    "nfs.service"
    "containerd.service"
    "smbd.service"
    "bind9.service"
    "openarena.service"
)

function list_units() {
    units=$(systemctl list-units --type=service --state=active)

    for service in "${potentially_unwanted_units[@]}"; do
        if echo "$units" | grep -iqw "$service"; then
            echo "Potentially unwanted service '$service' is enabled"
        fi
    done

    if prompt_y_n "Check enabled units for anything else unwanted [y/N]"; then
        systemctl list-units --type=service --state=active
    fi
}

# Hoping there aren't more or else they'll lose exec permissions...
files_needing_exec=(
    ".profile"
    ".bashrc"
    ".bash_logout"
    "hash.sh"
    "script.sh"
)

function verify_perms() {
    # These should be covered by the hashes but check them anyway just in case
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

    # This should catch sticky bits too I think because of -1000
    find "$perms_search_root" -xdev -type d \( -perm -0002 -a ! -perm -1000 \) > "$world_writeable_log"
    echo "Found $(wc -l < "$high_perm_log") world-writeable files in $perms_search_root!"

    find "$perms_search_root" -xdev \( -nouser -o -nogroup \) > "$no_user_log"
    echo "Found $(wc -l < "$high_perm_log") files missing a user or group in $perms_search_root!"

    find "$perms_search_root" -perm /u=s,g=s > "$setuid_gid_log"
    echo "Found $(wc -l < "$setuid_gid_log") files with setuid or setgid in $perms_search_root!"

    find "$perms_search_root" -perm -o=r > "$world_readable_log"
    echo "Found $(wc -l < "$world_readable_log") world-readable files in $perms_search_root!"
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

# Not sure if these parameters will work
lightdm_conf="/etc/lightdm/lightdm.conf"
lightdm_params=(
    "greeter-allow-guest=false"
    "greeter-hide-users=true"
    "greeter-show-manual-login=true"
    "allow-guest=false"
)

gdm3_conf="/etc/gdm3/greeter.dconf-defaults"
gdm3_params=(
    "disable-user-list=true"
    "disable-restart-buttons=true"
)

# Gdm3 custom is off because I shouldn't be turning off automatic login. What was I thinking
# gdm3_custom_conf="/etc/gdm3/custom.conf"
# gdm3_custom_params=(
#     "AutomaticLoginEnable=false"
# )

function display_manager() {
    if [ -f "$lightdm_conf" ]; then
        echo "Fixing $lightdm_conf settings"
        apply_params_list "=" "^::param::\s*=\s*true|false" "$lightdm_conf" "${lightdm_params[@]}"
    fi

    if [ -f "$gdm3_conf" ]; then
        echo "Fixing $gdm3_conf settings"
        apply_params_list "=" "^::param::\s*=\s*true|false" "$gdm3_conf" "${gdm3_params[@]}"
    fi

    # if [ -f "$gdm3_custom_conf" ]; then
    #     echo "Fixing $gdm3_custom_conf settings"
    #     apply_params_list "=" "^::param::\s*=\s*true|false" "$gdm3_custom_conf" "${gdm3_custom_params[@]}"
    # fi
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

function fail2ban() {
    if ! prompt_install "fail2ban"; then
        return
    fi

    systemctl enable --now fail2ban.service

    echo "Enabled fail2ban"
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
# TODO: Should add smb, ssh, vsftp, apache, php, mysql, postgresql and more secure configurations eventually

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
            readme_exp="Authorized Administrators:(.*?)<b>Authorized Users:<\/b>(.*?)<\/pre>"

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
            # Update: It works. I'm not killing myself
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
    list_disallowed_files
    kernel_parameters
    bad_software
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
    fail2ban
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
