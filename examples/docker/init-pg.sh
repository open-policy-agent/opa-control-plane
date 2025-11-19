#!/usr/bin/env bash
set -Eeo pipefail


pUID=$(id -u postgres)
pGID=$(id -g postgres)

if [ -z "$pUID" ]
then
    echo "Unable to find postgres user id, required in order to chown key material"
    exit 1
fi

if [ -z "$pGID" ]
then
    echo "Unable to find postgres group id, required in order to chown key material"
    exit 1
fi

chown "$pUID":"$pGID" -R /etc/ssl/postgresql/
/usr/local/bin/docker-entrypoint.sh "$@"
