#!/usr/bin/env bash

set -eE -o functrace

failure() {
  local lineno=$1
  local msg=$2
  echo "Failed at $lineno: $msg"
}
trap 'failure ${LINENO} "$BASH_COMMAND"' ERR

# Log file definitions
export log_base="./logs"
mkdir -p "$log_base"

# Shut up both commands
function pushd {
    command pushd "$@" >/dev/null || return
}

function popd {
    command popd >/dev/null || return
}

# Repeat a given character
function repl() {
    ret=""
    for ((i = 0; i < $2; i++)); do
        ret="$ret$1"
    done

    echo "$ret"
}

function get_users() {
    # The <65534 condition is to skip the nobody user
    awk -F: '{if ($3 >= 1000 && $3 < 65534) print $1}' </etc/passwd
}

function user_exists() {
    if id "$1" >/dev/null 2>&1; then
        return 0 # true
    else
        return 1 # false
    fi
}

# $1 pattern to match
# $2 text
# $3 file to check
function edit_or_append() {
    local bf="$3-bak"
    if [ -e "$3" ]; then
        if ! [ -e "$bf" ]; then
            echo "Backing up $3 to $bf"
            cp "$3" "$bf"
        else
            echo "Backup found at $bf"
        fi
    fi

    if grep -Eq "$1" "$3"; then
        sed -Ei "s\`$1\`$2\`g" "$3"
    else
        echo "$2" >>"$3"
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
        ;;
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
    . <({
        derr=$(
            { dout=$(dpkg -s "$1"); } 2>&1
            declare -p dout >&2
        )
        declare -p derr
    } 2>&1)

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
    local split_char="$1"
    shift
    local regex_template="$1"
    shift
    local config_file="$1"
    shift
    local params=("$@")

    for param_string in "${params[@]}"; do
        IFS="$split_char" read -ra split <<<"$param_string"

        local param="${split[0]}"
        local value="${split[1]}"
        local regex=${regex_template//::param::/$param}
        regex=${regex//::value::/$value}

        echo "Adding $param with value $value to $config_file, using regex ${regex}"
        edit_or_append "$regex" "$param_string" "$config_file"
    done
}

backup_dir="/etc/conf_backup"
# $1 the package name
# $2 the config directory to restore
function restore_and_backup_conf() {
    local pkg_backup_dir="$backup_dir/$1"
    mkdir -p "$pkg_backup_dir"

    echo "Backing up $2 to $pkg_backup_dir"
    cp -r "$2" "$pkg_backup_dir"

    echo "Restoring default config"

    apt install --reinstall -o Dpkg::Options::="--force-confask,confnew,confmiss" "$1"

    echo "Finished restoring config for $1"
}

# $1 element
# $2 array
function array_contains() {
    local test="$1"
    shift
    local array=("$@")
    for e in "${array[@]}"; do
        if [ "$e" = "$test" ]; then
            return 0 # true
        fi
    done

    return 1 # false
}

# $1 path
# $2 folder octal
# $3 file octal
function recurse_perms_inner() {
    for p in "$1/"*; do
        if [ -d "$p" ]; then
            chmod "$2" "$p"
            recurse_perms_inner "$p" "$2" "$3"
        elif [ -f "$p" ]; then
            chmod "$3" "$p"
        fi
    done
}

# $1 path
# $2 folder octal
# $3 file octal
# $4 user:group pair
function recurse_perms() {
    shopt -s nullglob dotglob

    echo "Setting permissions of files to $3 and folders to $2 within $1, setting owner to $4"

    chown -R "$4" "$1"
    recurse_perms_inner "$1" "$2" "$3"

    shopt -u nullglob dotglob
}

# $1 array of files
function view_all_files() {
    for file in "$@"; do
        prompt_y_n_quit "View contents of $file [y/N/q] "
        response=$?

        if [ $response -eq 0 ]; then
            less <"$file"
        elif [ $response -eq 2 ]; then
            break
        fi
    done
}

function is_mint() {
    if [ -e "/etc/issue" ] && grep -qw "Mint" </etc/issue; then
        return 0
    fi

    return 1
}

function os_name() {
    if uname -a | grep -iqw "ubuntu"; then
        echo "ubuntu"
        return
    fi

    if uname -a | grep -iqw "debian"; then
        echo "debian"
        return
    fi

    if is_mint; then
        echo "mint"
        return
    fi

    echo "Unknown operating system $(uname -a)"
    exit 1
}
