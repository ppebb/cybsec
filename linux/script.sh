#!/usr/bin/env bash

# Exit if something errors to avoid something going terribly wrong...
set -e

source ./utils.sh

sec_pass="rnXvDH2iAhiALoNbfdFDiLkfYpt8G3md"

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

    if [ -e "/etc/issue" ] && grep -qw "Mint" </etc/issue; then
        echo "Enabling automatic updates for Linux Mint"
        mintupdate-automation upgrade enable
    fi

    echo "Done configuring automatic updates!"
}

function firewall() {
    apt install ufw -y
    ufw default deny incoming
    ufw default allow outgoing
    ufw logging on
    ufw logging high
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
        . <({
            gerr=$(
                { gout=$(groups "$user"); } 2>&1
                declare -p gout >&2
            )
            declare -p gerr
        } 2>&1)

        if [ -n "$gerr" ]; then
            echo "Error '$gerr' when attempting to check groups of $user"
            continue
        fi

        for group in "${admin_groups[@]}"; do
            # shellcheck disable=2031
            if echo "$gout" | grep -qw "$group" && ! [[ "$admins" == *"$user"* ]]; then
                if prompt_y_n "User $user is part of group $group when they should not be. Remove them from the group? [y/N] "; then
                    echo "Removing $user from $group"
                    gpasswd -d "$user" "$group"
                fi
            fi
        done
    done

    for user in $admins; do
        # Don't need to check user_exists. This should catch everything I hope
        # shellcheck disable=1090
        . <({
            gerr=$(
                { gout=$(groups "$user"); } 2>&1
                declare -p gout >&2
            )
            declare -p gerr
        } 2>&1)

        if [ -n "$gerr" ]; then
            echo "Error '$gerr' when attempting to check groups of $user"
            continue
        fi

        if ! echo "$user" | grep -qw "admin\|wheel\|staff\|sudo\|sudoers\|adm\|lpadm"; then
            echo "User $user appears not to be an administrator when they should be"
        fi
    done

    printf "\n"
    printf "Check for weird admins:\n %s \n" "$(mawk -F: '$1 == "sudo"' /etc/group)"
    printf "Check for weird users:\n %s \n" "$(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd)"
    printf "Check for empty passwords:\n %s \n" "$(mawk -F: '$2 == ""' /etc/passwd)"
    printf "Check for empty passwords:\n %s \n" "$(mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd)"

    echo "Done managing users"
}

function change_passwords() {
    for user in $allowed_users; do
        if ! user_exists "$user"; then
            echo "Attempted to check user '$user', but they do not exist"
            continue
        fi

        echo "Changing password for $user"
        echo "$user:$sec_pass" | chpasswd
        echo "Clearing Finger for $user"
        chfn -f "" -h "" -o "" -r "" -w "" "$user"
    done

    for user in $admins; do
        if ! user_exists "$user"; then
            echo "Attempted to change password for admin '$user', but they do not exist"
        elif ! [[ "$vm_user" == "$user" ]]; then # WARN: This should probably work. But make sure you know this password just in case
            echo "Changing password for admin $user"
            echo "$user:$sec_pass" | chpasswd
            echo "Clearing Finger for admin $user"
            chfn -f "" -h "" -o "" -r "" -w "" "$user"
        fi
    done

    echo "Done changing passwords"
    echo "If the password hashing algorithm is updated, re-run this!"
}

login_params=(
    "FAILLOG_ENAB yes"
    "LOG_UNKFAIL_ENAB yes"
    "LOG_OK_LOGINS yes"
    "SYSLOG_SU_ENAB yes"
    "SYSLOG_SG_ENAB yes"
    "PASS_MAX_DAYS 14"
    "PASS_MIN_DAYS 7"
    "PASS_WARN_AGE 7"

    # Needs to match pam configuration
    "ENCRYPT-METHOD SHA512"

    # Overridden by pam. Set just in case!
    "LOGIN_RETRIES 5"
    "LOGIN_TIMEOUT 60"
    "CHFN_RESTRICT RWH"

    # Set restrictive umask
    "UMASK 027"
)

useradd_params=(
    "EXPIRE=30"
    "INACTIVE=30"
)

function expiry() {
    apply_params_list " " "^::param::\s*[a-zA-Z0-9]" "/etc/login.defs" "${login_params[@]}"

    users=$(get_users)
    for user in $users; do
        chage --mindays 7 --maxdays 14 --warndays 7 "$user"
    done

    apply_params_list " " "^::param::\s*=\s*[0-9]*)" "/etc/default/useradd" "${useradd_params[@]}"

    echo "Finished configuring login.defs and /etc/default/useradd"
}

commonpwd_conf="/etc/pam.d/common-password"
commonauth_conf="/etc/pam.d/common-auth"

# TODO: Make cracklib and pwquality have less redundant code because they do basically the same thing

pwstrength_opts="minlen=16 difok=4 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 gecoscheck=1 dictcheck=1 retry=3"
pam_unix_opts="obscure use_authtok try_first_pass sha512crypt remember=12"
pam_count_opts="deny=5 audit onerr=fail unlock_time=1800 even_deny_root"

libname=""
function setup_pam() {
    read -p "Configure cracklib or pwquality? [cracklib/pwquality] " response

    case "$response" in
    cracklib)
        echo "Configuring libpam-cracklib"

        if ! prompt_install "libpam-cracklib"; then
            return
        fi

        lib_sed="s/\(pam_cracklib\.so.*\)$/\1 $pwstrength_opts/"
        unix_sed="s/\(pam_unix\.so.*\)$/\1 $pam_unix_opts/"

        common_auth_string="auth required pam_tally2.so $pam_count_opts"

        libname="cracklib"
        ;;
    pwquality)
        echo "Configuring libpam-pwquality"

        if ! prompt_install "libpam-pwquality"; then
            return
        fi

        lib_sed="s/\(pam_pwquality\.so.*\)$/\1 $pwstrength_opts/"
        unix_sed="s/\(pam_unix\.so.*\)$/\1 $pam_unix_opts/"

        libname="pwquality"
        ;;
    *)
        echo "Unknown option selected, select either cracklib or pwquality"
        return
        ;;
    esac

    sed -i "$lib_sed" "$commonpwd_conf"
    sed -i "$unix_sed" "$commonpwd_conf"
    sed -i "s/nullok_secure//" "$commonpwd_conf"
    sed -i "s/yescrypt/sha512crypt/g" "$commonpwd_conf"
    # Remvoe null passwords
    sed -i "s/nullok//" "$commonauth_conf"

    if ! [[ -f "$commonauth_conf" ]] || ! grep -qw "$common_auth_string" <"$commonauth_conf"; then
        echo "$common_auth_string" >>"$commonauth_conf"
    fi

    echo "Updating passwords to fit new pam values!"
    change_passwords
    echo "Finished configuring libpam-$libname"

    echo "Disabling rhosts login in pam"
    echo "login auth required pam_rhosts_auth.so no_rhosts" >>/etc/pam.d/rlogin
}

function lock_root() {
    passwd -l root

    echo "Locked root account"
}

media_files_raw=("aa" "aac" "aax" "act" "aif" "aiff" "alac" "amr" "ape" "au" "awb" "dss" "dvf" "flac" "gsm" "iklax" "ivs" "m4a" "m4b" "mmf" "mp3" "mpc" "msv" "nmf" "ogg" "oga" "mogg" "opus" "ra" "raw" "rf64" "sln" "tta" "voc" "vox" "wav" "wma" "wv" "8svx" "cda" "webm" "mkv" "flv" "vob" "ogv" "ogg" "drc" "gif" "gifv" "mng" "avi" "mts" "m2ts" "mov" "qt" "wmv" "yuv" "rm" "rmvb" "viv" "asf" "amv" "mp4" "m4p" "m4v" "mpg" "mp2" "mpeg" "mpe" "mpv" "m2v" "svi" "3gp" "3g2" "mxf" "roq" 'nsv' "f4v" "f4p" "f4a" "f4b" "png" "jpg" "jpeg" "jfif" "exif" "tif" "tiff" "gif" "bmp" "ppm" "pgm" "pbm" "pnm" "webp" "heif" "avif" "ico" "tga" "psd" "xcf")

# TODO: Who the fuck wrote this I need to edit it
media_files=()

# Convert list of extensions to parameters for find command
for extension in "${media_files_raw[@]}"; do
    if [ $media_files ]; then media_files+=('-o'); fi
    media_files+=('-iname')
    media_files+=("*.$extension")
done

function list_disallowed_files() {
    find "/home/" -type f \( "${media_files[@]}" \) >"$media_files_log"

    find "/home/" -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \) >"$downloaded_packages_log"

    echo "Located media files and downloaded packages, written to logs"
}

kparams=(
    "kernel.randomize_va_space=2"

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
    "net.ipv4.conf.all.forwarding=0"

    # Log Martians
    "net.ipv4.conf.all.log_martians=1"
    "net.ipv4.conf.default.log_martians=1"
    "net.ipv4.icmp_ignore_bogus_error_responses=1"

    # Ignore ICMP redirects
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.secure_redirects=0"
    "net.ipv6.conf.all.secure_redirects=0"
    "net.ipv4.conf.default.secure_redirects=0"
    "net.ipv6.conf.default.secure_redirects=0"

    # Ignore Directed pings
    "net.ipv4.icmp_echo_ignore_all=1"

    # Additional config suggested by lynis
    "dev.tty.ldisc_autoload=0"
    "fs.protected_fifos=2"
    "fs.protected_hardlinks=1"
    "fs.protected_regular=2"
    "fs.protected_symlinks=1"
    "fs.suid_dumpable=0"
    "kernel.core_uses_pid=1"
    "kernel.ctrl-alt-del=0"
    "kernel.kptr_restrict=2"
    "kernel.modules_disabled=1"
    "kernel.perf_event_paranoid=2"
    "kernel.sysrq=0"
    "kernel.unprivileged_bpf_disabled=1"
    "kernel.yama.ptrace_scope=1"
    "net.core.bpf_jit_harden=2"
    "net.ipv4.conf.all.bootp_relay=0"
    "net.ipv4.conf.all.mc_forwarding=0"
    "net.ipv4.conf.all.proxy_arp=0"
    "net.ipv4.tcp_timestamps=0"

    # Might be bad
    #"fs.file-max=65535"
    "kernel.pid_max=65536"
    "net.core.netdev_max_backlog=5000"
    "net.core.rmem_max=8388608"
    "net.core.wmem_max=8388608"
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.default.rp_filter=1"
    "net.ipv4.ip_local_port_range=200065000"
    "net.ipv4.tcp_rmem=102408738012582912"
    "net.ipv4.tcp_window_scaling=1"
    "net.ipv4.tcp_wmem=102408738012582912"

    # NOTE: Disabling ipv6 might be helpful
    # "net.ipv6.conf.all.disable_ipv6=1"
    # "net.ipv6.conf.default.disable_ipv6=1"
    # "net.ipv6.conf.lo.disable_ipv6=1"

    "net.ipv6.conf.default.accept_ra_defrtr=0"
    "net.ipv6.conf.default.accept_ra_pinfo=0"
    "net.ipv6.conf.default.accept_ra_rtr_pref=0"
    "net.ipv6.conf.default.autoconf=0"
    "net.ipv6.conf.default.dad_transmits=0"
    "net.ipv6.conf.default.max_addresses=1"
    "net.ipv6.conf.default.router_solicitations=0"
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
        IFS="=" read -ra split <<<"$param_string"

        local param="${split[0]}"
        local value="${split[1]}"

        if [[ "$sysctl_out" != *"$param = $value"* ]]; then
            echo "parameter $param was not successfully set to $value"
        fi
    done

    echo "Finished checking kernel parameters in $kp_conf"

    echo "Restricting coredumps"
    echo "* hard core 0" >/etc/security/limits.d/custom.conf
}

bad_software_list=(
    "aircrack-ng"
    "deluge"
    "gameconqueror"
    "hashcat"
    "hydra"
    "john"
    "john-data"
    "nmap"
    "openvpn"
    "qbittorrent"
    "telnet"
    "wireguard"
    "zenmap"
    "ophcrack"
    "nc"
    "netcat"
    "netcat-openbsd"
    "nikto"
    "wireshark"
    "tcpdump"
    "netcat-traditional"
    "minetest"
    "fcrackzip"
    "ettercap"
    "vuze"
    "frostwire"
    "kismet"
    "freeciv"
    "minetest-server"
    "medusa"
    "truecrack"
    "cryptcat"
    "tightvncserver"
    "x11vnc"
)

function bad_software() {
    apt purge "${bad_software_list[@]}"

    echo "Removed disallowed software"
}

# TODO: add more because I keep forgetting
potentially_unwanted_software=(
    "openssh-server"
    "nginx"
    "apache"
    "apache2"
    "bind9"
    "caddy"
    "postfix"
    "sendmail"
    "vsftpd"
    "smbd"
    "lighttpd"
    "nfs"
    "samba"
    "mysql"
    "postgresql"
    "snmp"
    "dovecot"
)

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
        echo "$password" >>patterns
    done

    echo "Checking for files containing passwords"
    printf "Files containing passwords located in: \n%s" "$(rg --hidden --no-ignore --files-with-matches --fixed-strings -f patterns /home/)"
}

# This isn't even close to comprehensive. Should add more probably (definitely)
potentially_unwanted_units=(
    "nginx.service"
    "apache.service"
    "apache2.service"
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

    if prompt_y_n "Check enabled units for anything else unwanted [y/N] "; then
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
    # check_perm /etc/passwd 644 false
    # check_perm /etc/group 644 false
    # check_perm /etc/shadow 0 false

    chmod -R g-wx,o-rwx /var/log/*

    chown root:root /etc/ssh/sshd_config
    chmod og-rwx /etc/ssh/sshd_config

    chown root:root /etc/passwd
    chmod 644 /etc/passwd

    chown root:shadow /etc/shadow
    chmod o-rwx,g-wx /etc/shadow

    chown root:root /etc/group
    chmod 644 /etc/group

    chown root:shadow /etc/gshadow
    chmod o-rwx,g-rw /etc/gshadow

    chown root:root /etc/passwd-
    chmod 600 /etc/passwd-

    chown root:root /etc/shadow-
    chmod 600 /etc/shadow-

    chown root:root /etc/group-
    chmod 600 /etc/group-

    chown root:root /etc/gshadow-
    chmod 600 /etc/gshadow-

    chmod 700 /root
    chmod 600 /etc/securetty

    # Fix home directory permissions
    echo "Checking home directory permissions"
    for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do
        if [ ! -d "/home/${i}" ]; then
            echo "No home directory for user $i"
            continue
        else
            echo "Fixing permissions for directory /home/$i"
        fi

        # output to temp file because looping through find output is a pain in the ass otherwise...
        find "/home/${i}" >tmphomefiles

        while IFS= read -r file; do
            if [ -d "$file" ] || [[ "${files_needing_exec[*]}" == *$(basename "$file")* ]]; then
                chmod 700 "$file"
            elif [ -f "$file" ]; then
                chmod 600 "$file"
            fi
        done <tmphomefiles

        if [ -f tmphomefiles ]; then
            rm tmphomefiles
        fi

        local ssh_dir="/home/${i}/.ssh"
        if [ -d "$ssh_dir" ]; then
            chmod 700 "$ssh_dir"

            local auth_keys="$ssh_dir/authorized_keys"
            if [ -e "$auth_keys" ]; then
                chmod 600 "$auth_keys"
            fi

            local config="$ssh_dir/config"
            if [ -e "$config" ]; then
                chmod 600 "$config"
            fi

            local id="$ssh_dir/identity"
            if [ -e "$id" ]; then
                chmod 600 "$id"
            fi

            shopt -s nullglob

            for key in "$ssh_dir/"*_dsa; do
                echo "$sec_pass" | ssh-keygen -p -f "$key"
                chown 600 "$key"
            done

            for key in "$ssh_dir/"*_rsa; do
                echo "$sec_pass" | ssh-keygen -p -f "$key"
                chown 600 "$key"
            done

            for pubkey in "$ssh_dir/"*.pub; do
                chown 644 "$pubkey"
            done

            shopt -u nullglob
        fi
    done

    find "$perms_search_root" -type f -perm "-$high_perm_min" >"$high_perm_log"
    echo "Found $(wc -l <"$high_perm_log") files with permissions 700 or higher in $perms_search_root!"

    # This should catch sticky bits too I think because of -1000
    find "$perms_search_root" -xdev -type d \( -perm -0002 -a ! -perm -1000 \) >"$world_writeable_log"
    echo "Found $(wc -l <"$high_perm_log") world-writeable files in $perms_search_root!"

    find "$perms_search_root" -xdev \( -nouser -o -nogroup \) >"$no_user_log"
    echo "Found $(wc -l <"$high_perm_log") files missing a user or group in $perms_search_root!"

    find "$perms_search_root" -perm /u=s,g=s >"$setuid_gid_log"
    echo "Found $(wc -l <"$setuid_gid_log") files with setuid or setgid in $perms_search_root!"

    find "$perms_search_root" -perm -o=r >"$world_readable_log"
    echo "Found $(wc -l <"$world_readable_log") world-readable files in $perms_search_root!"

    echo "Setting sticky bit on all world-writeable directories"
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
}

function check_rc_local() {
    if [[ -f /etc/rc.local ]]; then
        echo "/etc/rc.local exists, check for anything unwanted"
        cat /etc/rc.local

        if prompt_y_n "Clear rc.local? [y/N]"; then
            echo "exit 0" >/etc/rc.local
        fi
    else
        echo "/etc/rc.local does not exist"
    fi
}

function disable_hardware() {
    echo "Disabling usb-storage, firewire, and thunderbolt"

    echo "install usb-storage /bin/true" >/etc/modprobe.d/disable-usb-storage.conf
    echo "blacklist firewire-core" >/etc/modprobe.d/firewire.conf
    echo "blacklist thunderbolt" >/etc/modprobe.d/thunderbolt.conf

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
            less <"$file"
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

function display_manager() {
    if [ -f "$lightdm_conf" ]; then
        echo "Fixing $lightdm_conf settings"
        apply_params_list "=" "^::param::\s*=\s*(true|false)" "$lightdm_conf" "${lightdm_params[@]}"
    fi

    if [ -f "$gdm3_conf" ]; then
        echo "Fixing $gdm3_conf settings"
        apply_params_list "=" "^::param::\s*=\s*(true|false)" "$gdm3_conf" "${gdm3_params[@]}"
    fi
}

function auditd() {
    if ! prompt_install "auditd"; then
        return
    fi

    auditctl -e 1

    echo "Enabled auditd"
}

function lynis() {
    if ! prompt_install "git"; then
        return
    fi

    cd /usr/local
    git clone https://github.com/CISOfy/lynis
    chown -R 0:0 /usr/local/lynis

    cd /usr/local/lynis
    lynis audit system

    echo "lynis log stored in /var/log/lynis-report.dat"
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
    if ! [ -d "./default_files/" ]; then
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

ssh_base="/etc/ssh"
sshd_conf="$ssh_base/sshd_config"
sshd_settings=(
    "LoginGraceTime 60"
    "PermitRootLogin no"
    "Protocol 2"
    "PermitEmptyPasswords no"
    "PasswordAuthentication yes"
    "X11Forwarding no"
    "UsePAM yes"
    "UsePrivilegeSeparation yes"
)

function sshd() {
    if ! prompt_install "openssh-server"; then
        return
    fi

    restore_and_backup_conf "openssh-server" "$ssh_base"

    apply_params_list " " "^::param::\s*[0-9a-zA-Z]*" "$sshd_conf" "${sshd_settings[@]}"

    local text
    text=$(cat "$sshd_conf")
    local regexp="[^#]Port\s*([0-9]*)"
    local port=""

    echo "Allowing sshd through ufw"

    if [[ $text =~ $regexp ]]; then
        port="${BASH_REMATCH[1]}"
    fi

    if [ -z "$port" ]; then
        echo "No port set in $sshd_conf, defaulting to 22"
        port="22"
    fi

    ufw allow "$port"

    systemctl enable ssh.service
    systemctl restart ssh.service
}

apache2_base="/etc/apache2"
apache2_conf="$apache2_base/apache2.conf"
apache2_settings=(
    # NOTE: Signature and Tokens may need to be set in /etc/apache2/conf-available/security.conf
    "ServerSignature Off"
    "ServerTokens Prod"
    "Timeout 45"
    "KeepAlive Off"
    "FileETag None"
    "TraceEnable off"
)

function apache2() {
    if ! prompt_install "apache2"; then
        return
    fi

    restore_and_backup_conf "apache2" "$apache2_base"

    apply_params_list " " "^::param::\s*[0-9a-zA-Z]*" "$apache2_conf" "${apache2_settings[@]}"

    recurse_perms "$apache2_base" 755 644 "root:root"

    echo "Allowing apache2 through ufw"
    ufw allow 80
    ufw allow 443

    systemctl enable apache2.service
    systemctl restart apache2.service
}

vsftpd_conf="/etc/vsftpd.conf"
vsftpd_settings=(
    "anonymous_enable=NO"
    "local_enable=YES"
    "write_enable=YES"
    "chroot_local_user=YES"
)

function vsftpd() {
    if ! prompt_install "vsftpd"; then
        return
    fi

    restore_and_backup_conf "vsftpd" "$vsftpd_conf"

    apply_params_list "=" "^::param::\s*=\s*(NO|YES)*" "$vsftpd_conf" "${vsftpd_settings[@]}"

    chmod 644 "$vsftpd_conf"
    chown root:root "$vsftpd_conf"

    echo "Allowing vsftpd through ufw"
    ufw allow 20
    ufw allow 21

    systemctl enable vsftpd.service
    systemctl restart vsftpd.service
}

function mysql() {
    false
}

function nginx() {
    false
}

psql_version_regex="Version: ([0-9]*)+"

function postgres() {
    if ! prompt_install "postgresql"; then
        return
    fi

    local psql_info
    psql_info=$(apt show postgresql 2>/dev/null)

    if [[ $psql_info =~ $psql_version_regex ]]; then
        psql_version=${BASH_REMATCH[1]}
    else
        echo "Unable to find psql version from apt, defaulting to 14"
        psql_version=14
    fi

    local psql_base="/etc/postgresql/$psql_version"
    local psql_conf="$psql_base/main/pg_hba.conf"

    restore_and_backup_conf "postgresql" "$psql_base"

    recurse_perms "$psql_base" 755 644 "postgres:postgres"

    echo "Forcing password for local connections"
    # change peer to scram-sha-256
    # local   all             all                                     peer
    sed -i "s/\(local\s*all\s*all\s*\)peer/\1scram-sha-256/" "$psql_conf"

    # change peer to scram-sha-256
    # local   replication     all                                     peer
    sed -i "s/\(local\s*replication\s*all\s*\)peer/\1scram-sha-256/" "$psql_conf"

    echo "Allowing postgresql through ufw"
    ufw allow 5432

    systemctl enable postgresql.service
    systemctl restart postgresql.service

    # IMPORTANT!!!!
    echo "Ensure to check for user mappings to the postgres user!!!"
}

smb_base="/etc/samba"
smb_conf="$smb_base/smb.conf"
smb_settings=(
    "global" "max log size" "1000"
    "global" "obey pam restrictions" "yes"
    "global" "map to guest" "never"
    "global" "usershare allow guests" "no"
    "global" "min protocol" "SMB2"
    "global" "smb encrypt" "required"
    "homes" "browseable" "no"
    "homes" "create mask" "0700"
    "homes" "directory mask" "0700"
    "homes" "valid users" "%S"
)

function samba() {
    if ! prompt_install "samba"; then
        return
    fi

    restore_and_backup_conf "samba" "$smb_base"

    recurse_perms "$smb_base" 755 644 "root:root"

    for ((i = 0; i < ${#smb_settings[@]}; i += 3)); do
        local section="${smb_settings[i]}"
        local section_safe="\\[$section\\]"
        section="[$section]"
        local setting="${smb_settings[i + 1]}"
        local value="${smb_settings[i + 2]}"
        echo "Setting $section $setting = $value"

        if grep -qw "$section_safe" <$smb_conf; then
            sed -i "s/^.*$section_safe$/$section_safe/" "$smb_conf"
        else
            echo "$section" >>"$smb_conf"
        fi

        # Clear any line setting the value we intend to set
        sed -i "s/^.*${setting}.*$//" "$smb_conf"

        # Put it at the beginning of the relevant section
        sed -i "s/$section_safe/$section\n$setting = $value/" "$smb_conf"
    done

    echo "Allowing smbd through ufw"

    ufw allow 139
    ufw allow 445

    systemctl enable smbd.service
    systemctl restart smbd.service
}

function watchccs() {
    if ! prompt_install "inotify-tools"; then
        return
    fi

    if [ -z $(pgrep -f "watchccs.sh") ]; then
        bash ./watchccs.sh
        return
    fi

    echo "ccs is already being watched! Check for logs in $log_base/ccs"
}

function stopwatchccs() {
    pid=$(pgrep -f "watchccs.sh")

    if [ -z "$pid" ]; then
        echo "ccs is not being monitored!"
    else
        kill "$pid"
        echo "Killed watchccs.sh"
    fi
}

# NOTE: I don't really know what this is doing or why it's here.
# username for grub authentication
grub_user="2oe"
# creates encrypted grub password (same as $sec_pass)
grub_pass=$(printf '%s\n%s' "$sec_pass" "$sec_pass" | grub-mkpasswd-pbkdf2 | tr -d '\n' | sed -e 's/Enter password: Reenter password: PBKDF2 hash of your password is //g')
function grub() {
    chown root:root /boot/grub/grub.cfg
    chmod 400 /boot/grub/grub.cfg

    echo "#!/bin/sh
exec tail -n +3 \$0

set superusers=\"$grub_user\"
password_pbkdf2 $grub_user $grub_pass" >/etc/grub.d/40_custom

    update-grub
}

function disable_ctrlaltdel() {
    echo "Masking ctrl-alt-del.target"
    systemctl mask ctrl-alt-del.target

    echo "exec true" >>/etc/init/control-alt-delete.override
    echo "Finished disabling ctrl-alt-del"
}

function reset_all_configs() {
    if [ -d "/etc-bak/" ]; then
        echo "Existing backup found at /etc-bak/, remove it before continuing!"
        return
    fi

    echo "Backing up existing configurations to /etc-bak/"
    mkdir -p /etc-bak/
    cp -r /etc/* /etc-bak/

    local packages=()
    for dir in /etc/*; do
        set +e
        local owners
        # shellcheck disable=2207
        owners=($(dpkg -S "$dir" 2>/dev/null | sed "s/,//g; s/:.*//"))
        set -e

        if [ -z "${owners[*]}" ]; then
            echo "Directory $dir is not owned by any packages, skipping..."
            continue
        fi

        for owner in "${owners[@]}"; do
            if ! array_contains "$owner" "${packages[@]}"; then
                packages+=("$owner")
            fi
        done
    done

    echo "Restoring config files for ${packages[*]}"
    apt install --reinstall -o Dpkg::Options::="--force-confask,confnew,confmiss" "${packages[@]}"
}

function print_help() {
    echo \
        "
ppeb's cyber patriot linux script!!!

Usage: script.sh [OPTIONS]
 --readme                      Link to grab readme from; will be parsed for authorized users and administrators
"
}

# SCRIPT BEGINS HERE!!!!!!

user=$(whoami)

if [ "$user" != "root" ]; then
    echo "Please run this as root!"
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
    -h | --help)
        print_help
        exit
        ;;
    #--users) ;; Unimplemented as it was useless
    --readme)
        readme_exp="Authorized Administrators:(.*?)<b>Authorized Users:<\/b>(.*?)<\/pre>"

        file=$(echo -n "$2" | md5sum | awk '{print $1}')
        file="$file.urlhash"

        # Hash the url and write it to a file so repeated requests aren't made
        if [ ! -e "$file" ]; then
            text=$(curl "$2")
            echo "$text" >"$file"
        else
            text=$(cat "$file")
        fi

        if [[ $text =~ $readme_exp ]]; then
            admins="${BASH_REMATCH[1]}"
            allowed_users="${BASH_REMATCH[2]}" # DOES NOT INCLUDE ADMINS

            admins=${admins#*$'\n'}
            # There should no longer be random newlines here
            allowed_users=$(echo "$allowed_users" | sed "s/\n//g" | sed "s/\r//g")
            passwords=$(echo "$admins" | grep "password" | sed "s/password: //g" | sed "s/^[ \t]*//")
            admins=$(echo "$admins" | grep -v "password" | sed "s/(you)//g" | tr -d "\r")
            vm_user=$(echo "$admins" | head -n1 | tr -cd "[:alnum:]._-")
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
    setup_pam
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
    lynis
    diff_default_files
    fail2ban
    sshd
    apache2
    vsftpd
    mysql
    nginx
    postgres
    samba
    watchccs
    stopwatchccs
    grub
    disable_ctrlaltdel
    reset_all_configs
)

funcs_len=${#funcs[@]}
funcs_strlen=${#funcs_len}

# $1 index
# $2 name
function fmt_entry() {
    # Spaces is length of the highest index minus length of current index
    prefix="($1)$(repl ' ' $((funcs_strlen - ${#i} + 1)))"
    line="$prefix$2"
    # Trailing spaces make each column 27 wide
    echo "$line$(repl ' ' $((27 - ${#line})))"
}

re='^[0-9]+$'
function menu() {
    echo

    for ((i = 0; i < ${#funcs[@]}; i += 2)); do
        line=$(fmt_entry "$i" "${funcs[i]}")
        if [ -n "${funcs[i + 1]}" ]; then
            line="$line$(fmt_entry "$((i + 1))" "${funcs[i + 1]}")"
        fi
        echo "$line"
    done
    read -r -p '> ' input

    if ! [[ $input =~ $re ]]; then
        echo "Please enter a number."
        return
    fi

    if [[ $input -ge "${#funcs[@]}" ]] || [[ $input -lt 0 ]]; then
        echo "Please enter a number from 0 to $((${#funcs[@]} - 1))"
        return
    fi

    echo
    ${funcs[$input]}
}

echo "ppeb's cybsec script. warranty not included, use at your own risk"
while true; do menu; done
