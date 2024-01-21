#!/usr/bin/env bash

set -e

# Log file definitions
export log_base="./logs"

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

function user_exists() {
    if id "$1" >/dev/null 2>&1; then
        return 0 # true
    else
        return 1 # false
    fi
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

