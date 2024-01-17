#!/usr/bin/env bash

directories=(
    "/etc"
    # What else to check...
)

function hash_all() {
    for dir in "${directories[@]}"; do
        files=$(find "$dir")

        for file in $files; do
            if [ -d "$file" ]; then
                continue
            fi

            xxh64sum "$file" >> "$1"
        done
    done
}

function check_all() {
    # Create a dictionary??
    declare -A sums_by_file

    # Check that all files in the provided hash file both exist and match
    while read -r line; do
        IFS="  " read -ra split <<< "$line"
        sum="${split[0]}"
        file="${split[1]}"

        sums_by_file[$file]=$sum

        if [ ! -e "$file" ]; then
            echo "$file" >> "missing.log"
            continue
        fi

        newsum=$(xxh64sum "$file")

        if [ "$line" != "$newsum" ]; then
            echo "$file" >> "changed.log"
        fi
    done < "$1"

    # Check for new files
    for dir in "${directories[@]}"; do
        files=$(find "$dir")

        for file in $files; do
            if [ -d "$file" ]; then
                continue
            fi

            if [ -z "${sums_by_file["$file"]}" ]; then
                echo "$file" >> "new.log"
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
