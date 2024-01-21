#!/usr/bin/env bash

set -e

source ./utils.sh

directories=(
    "/etc"
    #"/usr" # Don't check usr, has like 100k files...
    "/srv"
    "/opt"
    # What else to check...
)

# https://unix.stackexchange.com/questions/103920/parallelize-a-bash-for-loop
# initialize a semaphore with a given number of tokens
open_sem(){
    mkfifo pipe-$$
    exec 3<>pipe-$$
    rm pipe-$$
    local i=$1
    for((;i>0;i--)); do
        printf %s 000 >&3
    done
}

# run the given command asynchronously and pop/push tokens
run_with_lock(){
    local x
    # this read waits until there is something to read
    read -u 3 -n 3 x && ((0==x)) || exit "$x"
    (
     ( "$@"; )
    # push the return code of the command to the semaphore
    printf '%.3d' $? >&3
    )&
}

N=1000
function hash_inner() {
    perm=$(stat -c "%a" "$1")
    if [ -d "$1" ]; then
        if [ -n "$1" ]; then
            echo "d  $1  $perm" >> "$2"
        fi
        return
    fi

    sum=$(xxh64sum "$file")
    if [ -n "$sum" ]; then
        echo "$sum  $perm" >> "$2"
    fi
}

function hash_all() {
    if ! prompt_install "xxhash"; then
        exit 1
    fi

    echo "Hashing all files in ${directories[*]}"

    open_sem $N
    for dir in "${directories[@]}"; do
        files=$(find "$dir")

        for file in $files; do
            run_with_lock hash_inner "$file" "$1"
        done
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
        IFS="  " read -ra split <<< "$line"
        local file="${split[1]}"

        if [ "${split[0]}" = "d" ]; then
            local perm="${split[2]}"
        else
            local sum="${split[0]}"
            local perm="${split[2]}"
        fi

        if [ ! -e "$file" ]; then
            echo "$file" >> "$log_base/missing.log"
            continue
        fi

        local newperm
        newperm=$(stat -c "%a" "$file")

        if [ "$perm" != "$newperm" ]; then
            echo "$file changed permissions from $perm to $newperm" >> "$log_base/perms.log"
        fi

        if [ -v sum ] && [ ! -d "$file" ]; then
            sums_by_file[$file]=$sum

            newsum=$(xxh64sum "$file")

            if [ "$sum  $file" != "$newsum" ]; then
                echo "$file" >> "$log_base/changed.log"
            fi
        fi
    done < "$1"

    # Check for new files. We don't care about new directories because if they don't contain any files it should be fine...
    for dir in "${directories[@]}"; do
        files=$(find "$dir")

        for file in $files; do
            if [ -d "$file" ]; then
                continue
            fi

            # Sometimes gives false positives because of files that errored when hashing. Oh well.
            if [ -z "${sums_by_file["$file"]}" ]; then
                echo "$file" >> "$log_base/new.log"
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
        -h|--help)
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
