#!/usr/bin/env bash

set -e

source ./utils.sh

directories=(
    "/etc"
    "/usr"
    "/srv"
    "/opt"
    # What else to check...
)

function hash_inner() {
    perm=$(stat -c "%a" "$1")
    if [ -d "$1" ]; then
        if [ -n "$1" ]; then
            echo "d  $1  $perm"
        fi
        return
    fi

    sum=$(xxh64sum "$1")
    if [ -n "$sum" ]; then
        echo "$sum  $perm"
    fi
}
export -f hash_inner

function hash_all() {
    if ! (prompt_install "xxhash" && prompt_install "parallel"); then
        exit 1
    fi

    if [ -f "$1" ]; then
        if prompt_y_n "File '$1' already exists. Replace with new hashes? [y/N] "; then
            rm "$1"
        else
            return
        fi
    fi

    echo "Hashing all files in ${directories[*]}"

    for dir in "${directories[@]}"; do
        find "$dir" -print0 -not -xtype l | parallel -0 -j16 --pipe parallel -0 -j250 hash_inner {} >>"$1"
    done
}

function check_entry() {
    IFS="  " read -ra split <<<"$1"
    local file="${split[1]}"

    if [ "${split[0]}" = "d" ]; then
        local perm="${split[2]}"
    else
        local sum="${split[0]}"
        local perm="${split[2]}"
    fi

    if [ ! -e "$file" ]; then
        echo "$file" >>"$log_base/missing.log"
        return
    fi

    local newperm
    newperm=$(stat -c "%a" "$file")

    if [ "$perm" != "$newperm" ]; then
        echo "$file changed permissions from $perm to $newperm" >>"$log_base/perms.log"
    fi

    if [ -v sum ] && [ ! -d "$file" ]; then
        printf "%s\0%s" "$file" "$sum"

        newsum=$(xxh64sum "$file")

        if [ "$sum  $file" != "$newsum" ]; then
            echo "$file" >>"$log_base/changed.log"
        fi
    fi
}
export -f check_entry

function find_entry() {
    local -n sums_by_file_ref=$1

    if [ -d "$2" ]; then
        return
    fi

    # Sometimes gives false positives because of files that errored when hashing. Oh well.
    if [ -z "${sums_by_file_ref["$2"]}" ]; then
        echo "$2" >>"$log_base/new.log"
    fi
}

function check_all() {
    if ! (prompt_install "xxhash" && prompt_install "parallel"); then
        exit 1
    fi

    echo "Checking all files in ${directories[*]}"

    # Create a dictionary??
    declare -A sums_by_file

    # Check that all files in the provided hash file both exist and match
    while IFS= read -r line; do
        IFS=$'\0' read -ra split <<<"$line"
        sums_by_file["${split[0]}"]="${split[1]}"
    done <<<"$(parallel -j16 --pipe parallel -j250 check_entry {} <"$1")"

    # Check for new files. We don't care about new directories because if they don't contain any files it should be fine...
    for dir in "${directories[@]}"; do
        find "$dir" -print0 -not -xtype l | parallel -0 -j16 --pipe parallel -0 -j250 find_entry {} sums_by_file
    done
}

function print_help() {
    echo \
        "
ppeb's full filesystem checker linux script!!!

Usage: hash.sh --hash out_file OR hash.sh --check in_file

Good luck!
"
}

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

while [[ $# -gt 0 ]]; do
    case $1 in
    -h | --help)
        print_help
        exit
        ;;
    --hash)
        hash_all "$2"
        exit
        ;;
    --check)
        check_all "$2"
        exit
        ;;
    *)
        echo "Unknown argument $1"
        print_help
        exit
        ;;
    esac
done
