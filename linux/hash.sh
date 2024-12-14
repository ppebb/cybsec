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
        parallel_out=$(find "$dir" -print0 -not -xtype l | parallel -0 -j16 --pipe parallel -0 -j250 hash_inner {})
        echo "$parallel_out" >>"$1"
    done
}

# This cannot be parallelized easily because I need to assign stuff to sums_by_file... oh well
function check_all() {
    if ! prompt_install "xxhash"; then
        exit 1
    fi

    echo "Checking all files in ${directories[*]}"

    # Create a dictionary??
    declare -A sums_by_file

    # Check that all files in the provided hash file both exist and match
    while read -r line; do
        IFS="  " read -ra split <<<"$line"
        local file="${split[1]}"

        if [ "${split[0]}" = "d" ]; then
            local perm="${split[2]}"
        else
            local sum="${split[0]}"
            local perm="${split[2]}"
        fi

        if [ ! -e "$file" ]; then
            echo "$file" >>"$log_base/missing.log"
            continue
        fi

        local newperm
        newperm=$(stat -c "%a" "$file")

        if [ "$perm" != "$newperm" ]; then
            echo "$file changed permissions from $perm to $newperm" >>"$log_base/perms.log"
        fi

        if [ -v sum ] && [ ! -d "$file" ]; then
            sums_by_file[$file]=$sum

            newsum=$(xxh64sum "$file")

            if [ "$sum  $file" != "$newsum" ]; then
                echo "$file" >>"$log_base/changed.log"
            fi
        fi
    done <"$1"

    # Check for new files. We don't care about new directories because if they don't contain any files it should be fine...
    for dir in "${directories[@]}"; do
        files=$(find "$dir" -not -xtype l)

        for file in $files; do
            if [ -d "$file" ]; then
                continue
            fi

            # Sometimes gives false positives because of files that errored when hashing. Oh well.
            if [ -z "${sums_by_file["$file"]}" ]; then
                echo "$file" >>"$log_base/new.log"
            fi

        done
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
