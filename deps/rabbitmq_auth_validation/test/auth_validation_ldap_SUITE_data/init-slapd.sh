#!/bin/sh
# vim:sw=4:et:
#
# Minimal slapd setup for auth_validation integration tests.
# Adapted from deps/rabbitmq_auth_backend_ldap/test/system_SUITE_data/init-slapd.sh
#
# Usage: init-slapd.sh <data_dir> <tcp_port>

set -ex

readonly slapd_data_dir="$1"
readonly tcp_port="$2"

readonly pidfile="$slapd_data_dir/slapd.pid"
readonly uri="ldap://localhost:$tcp_port"

readonly binddn="cn=config"
readonly passwd=secret

case "$(uname -s)" in
    Darwin)
        # On macOS, slapd must already be running externally (e.g. in a
        # container) on the requested port.
        for seconds in 1 2 3 4 5 6 7 8 9 10; do
            ldapsearch -x -H "$uri" -b "" -s base namingContexts >/dev/null 2>&1 && break
            sleep 1
        done
        ldapsearch -x -H "$uri" -b "" -s base namingContexts >/dev/null 2>&1 || {
            echo "ERROR: no LDAP server reachable at $uri" >&2
            exit 1
        }
        echo "SLAPD_PID=0"
        exit 0
        ;;
    Linux)
        if [ -x /usr/bin/slapd ]
        then
            readonly slapd=/usr/bin/slapd
        elif [ -x /usr/sbin/slapd ]
        then
            readonly slapd=/usr/sbin/slapd
        fi

        if [ -d /usr/lib/openldap ]
        then
            readonly modulepath=/usr/lib/openldap
        elif [ -d /usr/lib/ldap ]
        then
            readonly modulepath=/usr/lib/ldap
        fi

        if [ -d /etc/openldap/schema ]
        then
            readonly schema_dir=/etc/openldap/schema
        elif [ -d /etc/ldap/schema ]
        then
            readonly schema_dir=/etc/ldap/schema
        fi
        ;;
    FreeBSD)
        readonly slapd=/usr/local/libexec/slapd
        readonly modulepath=/usr/local/libexec/openldap
        readonly schema_dir=/usr/local/etc/openldap/schema
        ;;
    *)
        exit 1
        ;;
esac

# --------------------------------------------------------------------
# slapd(8) configuration + start
# --------------------------------------------------------------------

rm -rf "$slapd_data_dir"
mkdir -p "$slapd_data_dir"

readonly conf_file="$slapd_data_dir/slapd.conf"
cat <<EOF > "$conf_file"
include         $schema_dir/core.schema
include         $schema_dir/cosine.schema
include         $schema_dir/inetorgperson.schema
pidfile         $pidfile
modulepath      $modulepath

database        mdb
directory       $slapd_data_dir/data
suffix          "dc=rabbitmq,dc=com"
rootdn          "cn=admin,dc=rabbitmq,dc=com"
rootpw          admin
EOF

mkdir -p "$slapd_data_dir/data"

# Start slapd(8).
"$slapd" \
    -f "$conf_file" \
    -h "$uri"

# Wait for the server to start.
for seconds in 1 2 3 4 5 6 7 8 9 10; do
    ldapsearch -x -H "$uri" -D "cn=admin,dc=rabbitmq,dc=com" -w admin \
        -b "dc=rabbitmq,dc=com" -s base dn >/dev/null 2>&1 && break
    sleep 1
done

echo "SLAPD_PID=$(cat "$pidfile")"
