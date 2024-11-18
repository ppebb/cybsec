#!/usr/bin/env bash

set -e
source ./utils.sh

set +e
pid="$(pidof ccs)"
set -e

if [ -z "$pid" ]; then
    echo "Unable to find pid of ccs!"
    exit 1
fi

echo "Found ccs pid: $pid"
echo "Monitoring ccs for open file handles!"
echo "Started monitoring ccs for open file handles. Logs stored in $log_base/ccs"

# Useful commands to keep in mind
# inotifywait -mcqr /proc/$$/fd/
# stat --format=%N /proc/1521314/fd/33
# pstree
