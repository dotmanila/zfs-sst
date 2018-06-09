#!/bin/bash -ue
# Copyright (C) 2013 Percona Inc
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston
# MA  02110-1301  USA.

##########################################################################
# If DEBUG_LOG is set, make this script to debug: set up the
# debug log and direct all output to it.  Otherwise, redirect to /dev/null.
# The log directory must be a directory, the log file must be writable and 
# not a symlink.
##########################################################################
DEBUG_LOG="/tmp/zfs-sst/log"
if [ "${DEBUG_LOG}" -a -w "${DEBUG_LOG}" -a ! -L "${DEBUG_LOG}" ]; then
   DEBUG_LOG_DIR="${DEBUG_LOG%/*}"
   if [ -d "${DEBUG_LOG_DIR}" ]; then
      exec 9>>"$DEBUG_LOG"
      exec 2>&9
      echo '=====================================================' >&9
      date >&9
      echo "$*" >&9
      set -x
   else
      exec 9>/dev/null
   fi
fi


. $(dirname $0)/wsrep_sst_common

ealgo=""
ekey=""
ekeyfile=""
encrypt=0
nproc=1
ecode=0
ssyslog=""
ssystag=""
SST_PORT=""
REMOTEIP=""
tca=""
tcert=""
tkey=""
sockopt=""
ncsockopt=""
progress=""
ttime=0
totime=0
lsn=""
ecmd=""
rlimit=""
# Initially
stagemsg="${WSREP_SST_OPT_ROLE}"
cpat=""
ib_home_dir=""
ib_log_dir=""
ib_undo_dir=""

sfmt="tar"
strmcmd=""
tfmt=""
tcmd=""
rebuild=0
rebuildcmd=""
payload=0
pvformat="-F '%N => Rate:%r Avg:%a Elapsed:%t %e Bytes: %b %p' "
pvopts="-f  -i 10 -N $WSREP_SST_OPT_ROLE "

uextra=0
disver=""

# Root directory for temporary files. This directory (and everything in it)
# will be removed upon exit.
tmpdirbase=""

# tmpdir used as target-dir for xtrabackup by the donor
itmpdir=""

scomp=""
sdecomp=""
ssl_dhparams=""

ssl_cert=""
ssl_ca=""
ssl_key=""

# Required for backup locks
# For backup locks it is 1 sent by joiner
# 5.6.21 PXC and later can't donate to an older joiner
sst_ver=1

if which pv &>/dev/null && pv --help | grep -q FORMAT;then 
    pvopts+=$pvformat
fi
pcmd=""
declare -a RC

ZFS_BIN='/usr/bin/sudo /sbin/zfs'
ZPOOL_MYSQL_BIN='/usr/bin/sudo /sbin/zpool'
DATA="${WSREP_SST_OPT_DATA}"
INFO_FILE="galera_info"
IST_FILE="galera_ist"

# This is the full path to the galera GTID info
# This is emitted by XtraBackup (for SST) or passed to us (for IST)
MAGIC_FILE="${DATA}/${INFO_FILE}"

# Used to send a file containing info about the SST
# Extend this if you want to send additional information
# from the donor to the joiner
SST_INFO_FILE="sst_info"

# Setting the path for ss and ip
export PATH="/usr/sbin:/sbin:$PATH"

timeit(){
    local stage=$1
    shift
    local cmd="$@"
    local x1 x2 took extcode

    if [[ $ttime -eq 1 ]];then 
        x1=$(date +%s)
        wsrep_log_info "Evaluating $cmd"
        eval "$cmd"
        extcode=$?
        x2=$(date +%s)
        took=$(( x2-x1 ))
        wsrep_log_info "NOTE: $stage took $took seconds"
        totime=$(( totime+took ))
    else 
        wsrep_log_info "Evaluating $cmd"
        eval "$cmd"
        extcode=$?
    fi
    return $extcode
}

get_keys()
{
    # $encrypt -eq 1 is for internal purposes only
    # ecmd sets the command to pipe encryption to
    # we just return for now, no support for encrypted transfers at the moment
    # we might need this for IST and SST_INFO_FILE transfers
    return

    if [[ $encrypt -ge 2 || $encrypt -eq -1 ]];then 
        return 
    fi

    if [[ $encrypt -eq 0 ]];then 
        if $MY_PRINT_DEFAULTS -c $WSREP_SST_OPT_CONF xtrabackup | grep -q encrypt;then
            wsrep_log_error "Unexpected option combination. SST may fail. Refer to http://www.percona.com/doc/percona-xtradb-cluster/manual/xtrabackup_sst.html "
        fi
        return
    fi

    if [[ $sfmt == 'tar' ]];then
        wsrep_log_info "NOTE: Xtrabackup-based encryption - encrypt=1 - cannot be enabled with tar format"
        encrypt=-1
        return
    fi

    wsrep_log_info "Xtrabackup based encryption enabled in my.cnf - Supported only from Xtrabackup 2.1.4"

    if [[ -z $ealgo ]];then
        wsrep_log_error "FATAL: Encryption algorithm empty from my.cnf, bailing out"
        exit 3
    fi

    if [[ -z $ekey && ! -r $ekeyfile ]];then
        wsrep_log_error "FATAL: Either key or keyfile must be readable"
        exit 3
    fi

    if [[ -z $ekey ]];then
        ecmd="xbcrypt --encrypt-algo=$ealgo --encrypt-key-file=$ekeyfile"
    else
        wsrep_log_warning "Using the 'encrypt-key' option causes the encryption key"
        wsrep_log_warning "to be set via the command-line and is considered insecure."
        wsrep_log_warning "It is recommended to use the 'encrypt-key-file' option instead."

        ecmd="xbcrypt --encrypt-algo=$ealgo --encrypt-key=$ekey"
    fi

    if [[ "$WSREP_SST_OPT_ROLE" == "joiner" ]];then
        ecmd+=" -d"
    fi

    stagemsg+="-XB-Encrypted"
}

#
# If the ssl_dhparams variable is already set, uses that as a source
# of dh parameters for OpenSSL. Otherwise, looks for dhparams.pem in the
# datadir, and creates it there if it can't find the file.
# No input parameters
#
check_for_dhparams()
{
    if [[ -z "$ssl_dhparams" ]]; then
        if ! [[ -r "$DATA/dhparams.pem" ]]; then
            wsrep_check_programs openssl
            wsrep_log_info "Could not find dhparams file, creating $DATA/dhparams.pem"

            if ! openssl dhparam -out "$DATA/dhparams.pem" 2048 >/dev/null 2>&1
            then
                wsrep_log_error "******** FATAL ERROR ********************************* "
                wsrep_log_error "* Could not create the dhparams.pem file with OpenSSL. "
                wsrep_log_error "****************************************************** "
                exit 22
            fi
        fi
        ssl_dhparams="$DATA/dhparams.pem"
    fi
}

#
# verifies that the certificate matches the private key
# doing this will save us having to wait for a timeout that would
# otherwise occur.
#
# 1st param: path to the cert
# 2nd param: path to the private key
#
verify_cert_matches_key()
{
    local cert_path=$1
    local key_path=$2

    wsrep_check_programs openssl diff

    # generate the public key from the cert and the key
    # they should match (otherwise we can't create an SSL connection)
    if ! diff <(openssl x509 -in "$cert_path" -pubkey -noout) <(openssl rsa -in "$key_path" -pubout 2>/dev/null) >/dev/null 2>&1
    then
        wsrep_log_error "******** FATAL ERROR ************************* "
        wsrep_log_error "* The certifcate and private key do not match. "
        wsrep_log_error "* Please check your certificate and key files. "
        wsrep_log_error "********************************************** "
        exit 22
    fi
}

# Checks to see if the file exists
# If the file does not exist (or cannot be read), issues an error
# and exits
#
# 1st param: file name to be checked (for read access)
# 2nd param: 1st error message (header)
# 3rd param: 2nd error message (footer, optional)
#
verify_file_exists()
{
    local file_path=$1
    local error_message1=$2
    local error_message2=$3

    if ! [[ -r "$file_path" ]]; then
        wsrep_log_error "******** FATAL ERROR ************************* "
        wsrep_log_error "* $error_message1 "
        wsrep_log_error "* Could not find/access : $file_path "

        if ! [[ -z "$error_message2" ]]; then
            wsrep_log_error "* $error_message2 "
        fi

        wsrep_log_error "********************************************** "
        exit 22
    fi
}

get_transfer()
{
    if [[ -z $SST_PORT ]];then 
        TSST_PORT=4444
    else 
        TSST_PORT=$SST_PORT
    fi

    if [[ ! -x `which nc` ]];then
        wsrep_log_error "nc(netcat) not found in path: $PATH"
        exit 2
    fi

    if [[ ! -x `which mbuffer` ]];then
        wsrep_log_error "mbuffer not found in path: $PATH"
        exit 2
    fi

    if [[ "$WSREP_SST_OPT_ROLE"  == "joiner" ]];then
        wsrep_log_info "Using netcat as streamer"
        if nc -h 2>&1 | grep -q ncat; then
            tcmd="nc $ncsockopt -l ${TSST_PORT}"
        else 
            tcmd="nc $ncsockopt -dl ${TSST_PORT}"
        fi

    elif [[ "$WSREP_SST_OPT_ROLE"  == "donor" ]];then
        wsrep_log_info "Using netcat as streamer"
        # netcat doesn't understand [] around IPv6 address
        tcmd="nc ${REMOTEIP//[\[\]]/} ${TSST_PORT}"

    elif [[ "$WSREP_SST_OPT_ROLE"  == "recvr" ]];then
        wsrep_log_info "Using mbuffer as streamer"
        tcmd="mbuffer -s 256k -m 1G -I ${TSST_PORT}"
    else
        wsrep_log_info "Using mbuffer as streamer"
        tcmd="mbuffer -s 256k -m 1G -O ${REMOTEIP//[\[\]]/}:${TSST_PORT}"
    fi
}

get_footprint()
{
    if [[ -z "$pcmd" ]]; then
        return
    fi
    pushd $WSREP_SST_OPT_DATA 1>/dev/null
    payload=$(find . -regex '.*\.ibd$\|.*\.MYI$\|.*\.MYD$\|.*ibdata1$' -type f -print0 | xargs -0 du --block-size=1 -c | awk 'END { print $1 }')
    if $MY_PRINT_DEFAULTS -c $WSREP_SST_OPT_CONF xtrabackup | grep -q -- "--compress";then 
        # QuickLZ has around 50% compression ratio
        # When compression/compaction used, the progress is only an approximate.
        payload=$(( payload*1/2 ))
    fi
    popd 1>/dev/null
    pcmd+=" -s $payload"
    adjust_progress
}

adjust_progress()
{
    if [[ -z "$pcmd" ]]; then
        return
    fi
    if [[ -n $progress && $progress != '1' ]];then 
        if [[ -e $progress ]];then 
            pcmd+=" 2>>$progress"
        else 
            pcmd+=" 2>$progress"
        fi
    elif [[ -z $progress && -n $rlimit  ]];then 
        # When rlimit is non-zero
        pcmd="pv -q"
    fi 

    if [[ -n $rlimit && "$WSREP_SST_OPT_ROLE"  == "donor" ]];then
        wsrep_log_info "Rate-limiting SST to $rlimit"
        pcmd+=" -L \$rlimit"
    fi
}

read_cnf()
{
    sfmt=$(parse_cnf sst streamfmt "xbstream")
    tfmt=$(parse_cnf sst transferfmt "socat")
    tca=$(parse_cnf sst tca "")
    tcert=$(parse_cnf sst tcert "")
    tkey=$(parse_cnf sst tkey "")
    encrypt=$(parse_cnf sst encrypt 0)
    sockopt=$(parse_cnf sst sockopt "")
    ncsockopt=$(parse_cnf sst ncsockopt "")
    rebuild=$(parse_cnf sst rebuild 0)
    ttime=$(parse_cnf sst time 0)

    # If pv is not in the PATH, then disable the 'progress'
    # and 'rlimit' options
    progress=$(parse_cnf sst progress "")
    rlimit=$(parse_cnf sst rlimit "")
    if [[ -n "$progress" ]] || [[ -n "$rlimit" ]]; then
        pcmd="pv $pvopts"
        if [[ ! -x `which pv` ]]; then
            wsrep_log_error "pv not found in path: $PATH"
            wsrep_log_error "Disabling all progress/rate-limiting"
            pcmd=""
            rlimit=""
            progress=""
        fi
    fi

    ealgo=$(parse_cnf sst encrypt-algo "")
    ekey=$(parse_cnf sst encrypt-key "")
    ekeyfile=$(parse_cnf sst encrypt-key-file "")

    # Pull the parameters needed for encrypt=4
    ssl_ca=$(parse_cnf sst ssl-ca "")
    if [[ -z "$ssl_ca" ]]; then
        ssl_ca=$(parse_cnf mysqld ssl-ca "")
    fi
    ssl_cert=$(parse_cnf sst ssl-cert "")
    if [[ -z "$ssl_cert" ]]; then
        ssl_cert=$(parse_cnf mysqld ssl-cert "")
    fi
    ssl_key=$(parse_cnf sst ssl-key "")
    if [[ -z "$ssl_key" ]]; then
        ssl_key=$(parse_cnf mysqld ssl-key "")
    fi

    ssl_dhparams=$(parse_cnf sst ssl-dhparams "")

    ssyslog=$(parse_cnf sst sst-syslog 0)
    ssystag=$(parse_cnf mysqld_safe syslog-tag "${SST_SYSLOG_TAG:-}")
    ssystag+="-"

    if [[ $ssyslog -ne -1 ]];then 
        if my_print_defaults -c $WSREP_SST_OPT_CONF mysqld_safe | tr '_' '-' | grep -q -- "--syslog";then 
            ssyslog=1
        fi
    fi

    # Retry the connection 30 times (at 1-second intervals)
    if [[ ! "$sockopt" =~ retry= ]]; then
        sockopt+=",retry=30"
    fi

}

#
# Fills in strmcmd, which holds the command used for streaming
#
# Note:
#   This code creates a command that uses FILE_TO_STREAM
#
get_stream()
{
    sfmt="tar"
    wsrep_log_info "Streaming with tar"
    if [[ "$WSREP_SST_OPT_ROLE"  == "joiner" ]];then
        strmcmd="tar xfi - "
    elif [[ "$WSREP_SST_OPT_ROLE"  == "donor" ]];then
        strmcmd="tar cf - \${FILE_TO_STREAM} "
    elif [[ "$WSREP_SST_OPT_ROLE"  == "sendr" ]];then
        strmcmd="$ZFS_BIN send -r mysql@sst"
    elif [[ "$WSREP_SST_OPT_ROLE"  == "recvr" ]];then
        strmcmd="$ZFS_BIN recv -F mysql"
    fi
}

get_proc()
{
    set +e
    nproc=$(grep -c processor /proc/cpuinfo)
    [[ -z $nproc || $nproc -eq 0 ]] && nproc=1
    set -e
}

sig_joiner_cleanup()
{
    wsrep_log_error "Removing $MAGIC_FILE file due to signal"
    rm -f "$MAGIC_FILE"
}

cleanup_joiner()
{
    # Since this is invoked just after exit NNN
    local estatus=$?
    if [[ $estatus -ne 0 ]];then 
        wsrep_log_error "Cleanup after exit with status:$estatus"
    fi
    if [[ -n $progress && -p $progress ]];then 
        wsrep_log_info "Cleaning up fifo file $progress"
        rm $progress
    fi
    if [[ -n "${tmpdirbase}" ]]; then
        [[ -d "${tmpdirbase}" ]] && find "${tmpdirbase}/" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} \; || true
    fi

    # Final cleanup 
    pgid=$(ps -o pgid= $$ | grep -o '[0-9]*')

    # This means no setsid done in mysqld.
    # We don't want to kill mysqld here otherwise.
    if [[ $$ -eq $pgid ]];then

        # This means a signal was delivered to the process.
        # So, more cleanup. 
        if [[ $estatus -ge 128 ]];then 
            kill -KILL -$$ || true
        fi

    fi

    exit $estatus
}

cleanup_donor()
{
    # Since this is invoked just after exit NNN
    local estatus=$?
    if [[ $estatus -ne 0 ]];then 
        wsrep_log_error "Cleanup after exit with status:$estatus"
    fi

    rm -f ${DATA}/${IST_FILE} || true

    if [[ -n $progress && -p $progress ]];then 
        wsrep_log_info "Cleaning up fifo file $progress"
        rm -f $progress || true
    fi

    wsrep_log_info "Cleaning up temporary directories"

    if [[ -n "${tmpdirbase}" ]]; then
        [[ -d "${tmpdirbase}" ]] && find "${tmpdirbase}/" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} \; || true
    fi

    # Final cleanup 
    pgid=$(ps -o pgid= $$ | grep -o '[0-9]*')

    # This means no setsid done in mysqld.
    # We don't want to kill mysqld here otherwise.
    if [[ $$ -eq $pgid ]];then

        # This means a signal was delivered to the process.
        # So, more cleanup. 
        if [[ $estatus -ge 128 ]];then 
            kill -KILL -$$ || true
        fi

    fi

    exit $estatus

}

setup_ports()
{
    if [[ "$WSREP_SST_OPT_ROLE"  == "donor" || "$WSREP_SST_OPT_ROLE"  == "sendr" ]];then
        SST_PORT=$WSREP_SST_OPT_PORT
        REMOTEIP=$WSREP_SST_OPT_HOST
        lsn=$(echo $WSREP_SST_OPT_PATH | awk -F '[/]' '{ print $2 }')
        sst_ver=$(echo $WSREP_SST_OPT_PATH | awk -F '[/]' '{ print $3 }')
    else
        SST_PORT=$WSREP_SST_OPT_PORT
    fi
}

# waits ~1 minute for nc/socat to open the port and then reports ready
# (regardless of timeout)
wait_for_listen()
{
    local HOST=$1
    local PORT=$2
    local MODULE=$3

    for i in {1..300}
    do
        if [ "`uname`" = "FreeBSD" ] ; then
            get_listening_on_port_cmd="sockstat -l -P tcp -p $PORT"
        else
            get_listening_on_port_cmd="ss -p state listening ( sport = :$PORT )"
        fi

        if [[ "$WSREP_SST_OPT_ROLE"  == "recvr" ]];then
            $get_listening_on_port_cmd | grep -qE 'mbuffer' && break
        elif [[ "$WSREP_SST_OPT_ROLE"  == "joiner" ]];then
            $get_listening_on_port_cmd | grep -qE 'nc' && break
        fi

        sleep 0.2
    done

    echo "ready ${HOST}:${PORT}/${MODULE}//$sst_ver"
}

check_extra() 
{ 
    return
}

recv_joiner()
{
    local dir=$1
    local msg=$2 
    local tmt=$3
    local checkf=$4
    local ltcmd

    if [[ ! -d ${dir} ]];then
        # This indicates that IST is in progress
        return
    fi

    pushd ${dir} 1>/dev/null
    set +e

    if [[ $tmt -gt 0 && -x `which timeout` ]];then 
        if timeout --help | grep -q -- '-k';then 
            ltcmd="timeout -k $(( tmt+10 )) $tmt $tcmd"
        else 
            ltcmd="timeout -s9 $tmt $tcmd"
        fi
        timeit "$msg" "$ltcmd | $strmcmd; RC=( "\${PIPESTATUS[@]}" )"
    else 
        timeit "$msg" "$tcmd | $strmcmd; RC=( "\${PIPESTATUS[@]}" )"
    fi

    set -e
    popd 1>/dev/null 

    if [[ ${RC[0]} -eq 124 ]];then 
        wsrep_log_error "Possible timeout in receving first data from donor in gtid stage"
        exit 32
    fi

    for ecode in "${RC[@]}";do 
        if [[ $ecode -ne 0 ]];then 
            wsrep_log_error "Error while getting data from donor node: " \
                            "exit codes: ${RC[@]}"
            exit 32
        fi
    done

    if [[ $checkf -eq 1 && ! -r "${MAGIC_FILE}" ]];then
        # this message should cause joiner to abort
        wsrep_log_error "xtrabackup process ended without creating '${MAGIC_FILE}'"
        wsrep_log_info "Contents of datadir" 
        wsrep_log_info "$(ls -l ${dir}/*)"
        exit 32
    fi
}

recv_zfs()
{
    local dir=$1
    local msg=$2 
    local tmt=$3
    local checkf=$4
    local ltcmd

    if [[ ! -d ${dir} ]];then
        # This indicates that IST is in progress
        return
    fi

    pushd ${dir} 1>/dev/null
    set +e

    if [[ $tmt -gt 0 && -x `which timeout` ]];then 
        if timeout --help | grep -q -- '-k';then 
            ltcmd="timeout -k $(( tmt+10 )) $tmt $tcmd"
        else 
            ltcmd="timeout -s9 $tmt $tcmd"
        fi
        timeit "$msg" "$ltcmd | $strmcmd; RC=( "\${PIPESTATUS[@]}" )"
    else 
        timeit "$msg" "$tcmd | $strmcmd; RC=( "\${PIPESTATUS[@]}" )"
    fi

    set -e
    popd 1>/dev/null 

    if [[ ${RC[0]} -eq 124 ]];then 
        wsrep_log_error "Possible timeout in receving first data from donor in gtid stage"
        exit 32
    fi

    for ecode in "${RC[@]}";do 
        if [[ $ecode -ne 0 ]];then 
            wsrep_log_error "Error while getting data from donor node: " \
                            "exit codes: ${RC[@]}"
            exit 32
        fi
    done

    if [[ $checkf -eq 1 && ! -r "${MAGIC_FILE}" ]];then
        # this message should cause joiner to abort
        wsrep_log_error "xtrabackup process ended without creating '${MAGIC_FILE}'"
        wsrep_log_info "Contents of datadir" 
        wsrep_log_info "$(ls -l ${dir}/*)"
        exit 32
    fi
}


#
# Send data from the donor to the joiner
#
# Parameters:
#   1 : dir - the base directory (paths are based on this)
#   2 : msg - descriptive message
#
send_donor()
{
    local dir=$1
    local msg=$2 

    pushd ${dir} 1>/dev/null
    set +e
    timeit "$msg" "$strmcmd | $tcmd; RC=( "\${PIPESTATUS[@]}" )"
    set -e
    popd 1>/dev/null 


    for ecode in "${RC[@]}";do 
        if [[ $ecode -ne 0 ]];then 
            wsrep_log_error "Error while getting data from donor node: " \
                            "exit codes: ${RC[@]}"
            exit 32
        fi
    done

}

# Returns the version string in a standardized format
# Input "1.2.3" => echoes "010203"
# Wrongly formatted values => echoes "000000"
normalize_version()
{
    local major=0
    local minor=0
    local patch=0

    # Only parses purely numeric version numbers, 1.2.3 
    # Everything after the first three values are ignored
    if [[ $1 =~ ^([0-9]+)\.([0-9]+)\.?([0-9]*)([\.0-9])*$ ]]; then
        major=${BASH_REMATCH[1]}
        minor=${BASH_REMATCH[2]}
        patch=${BASH_REMATCH[3]}
    fi

    printf %02d%02d%02d $major $minor $patch
}

# Compares two version strings
# The first parameter is the version to be checked
# The second parameter is the minimum version required
# Returns 0 (success) if $1 >= $2, 1 (failure) otherwise
check_for_version()
{
    local local_version_str="$( normalize_version $1 )"
    local required_version_str="$( normalize_version $2 )"

    if [[ "$local_version_str" < "$required_version_str" ]]; then
        return 1
    else
        return 0
    fi
}

#
# Initiailizes the tmpdir
# Reads the info from the config file and creates the tmpdir as needed.
#
# Sets the $tmpdirbase variable to the root of the temporary directory
# to be used by SST. 
#
# This directory is mandatory for ZFS SST snapshots, the script cannot
# write to the same data directory where the snapshot will be restored/streamed
# It needs to be on a different device/partition/disk outside of the mysql parent dataset
#
initialize_tmpdir()
{
    local tmpdir_path=""

    tmpdir_path=$(parse_cnf sst tmpdir "")

    if [[ -n "${tmpdir_path}" ]]; then
        if [[ ! -d "${tmpdir_path}" ]]; then
            wsrep_log_error "Cannot find the directory, ${tmpdir_path}, the tmpdir must exist before startup."
            exit 2
        fi
        if [[ ! -r "${tmpdir_path}" ]]; then
            wsrep_log_error "The temporary directory, ${tmpdir_path}, is not readable.  Please check the directory permissions."
            exit 22
        fi
        if [[ ! -w "${tmpdir_path}" ]]; then
            wsrep_log_error "The temporary directory, ${tmpdir_path}, is not writable.  Please check the directory permissions."
            exit 22
        fi
    fi

    # Everything in this directory will be removed upon exit
    tmpdirbase=$tmpdir_path
}


#
# Parses the passed in config file and returns the option in the
# specified group.
#
# 1st param: source_path : path the the source file
# 2nd param: group : name of the config file section, e.g. mysqld
# 3rd param: var : name of the variable in the section, e.g. server-id
# 4th param: - : default value for the param
#
parse_sst_info()
{
    local source_path=$1
    local group=$2
    local var=$3
    local reval=""

    # print the default settings for given group using my_print_default.
    # normalize the variable names specified in cnf file (user can use _ or -
    # for example log-bin or log_bin) then grep for needed variable
    # finally get the variable value (if variables has been specified
    # multiple time use the last value only)

    reval=$($MY_PRINT_DEFAULTS -c "$source_path" $group | awk -F= '{if ($1 ~ /_/) { gsub(/_/,"-",$1); print $1"="$2 } else { print $0 }}' | grep -- "--$var=" | cut -d= -f2- | tail -1)

    # use default if we haven't found a value
    if [[ -z $reval ]]; then
        [[ -n $4 ]] && reval=$4
    fi

    echo $reval
}




if [[ ! -x `which zfs` ]];then 
    wsrep_log_error "zfs not in path: $PATH"
    exit 2
fi

# Check if the mysql zpool exists, this pool name can be change in the future
ZPOOL_MYSQL=$(sudo /sbin/zpool list | egrep -o '^mysql\s')
ZFS_VERSION=$(modinfo zfs | egrep '^version:' | cut -d: -f2 | egrep -o '[0-9]\.[0-9][\.0-9].')

if [[ -z $ZPOOL_MYSQL ]]; then
    wsrep_log_error "FATAL: zpool named mysql does not exist!"
    exit 2
fi

# Get our MySQL version
MYSQL_VERSION=$($(dirname $0)/mysqld --version 2>&1 | grep -oe '[0-9]\.[0-9][\.0-9]*' | head -n1)

rm -f "${MAGIC_FILE}"

if [[ ! ${WSREP_SST_OPT_ROLE} == 'joiner' && ! ${WSREP_SST_OPT_ROLE} == 'donor' && ! ${WSREP_SST_OPT_ROLE} == 'recvr' && ! ${WSREP_SST_OPT_ROLE} == 'sendr' ]];then 
    wsrep_log_error "Invalid role ${WSREP_SST_OPT_ROLE}"
    exit 22
fi

read_cnf
setup_ports

get_stream
get_transfer

if [ "$WSREP_SST_OPT_ROLE" = "donor" ]
then
    trap cleanup_donor EXIT

    initialize_tmpdir

    # main temp directory for SST (non-XB) related files
    donor_tmpdir=$(mktemp -p "${tmpdirbase}" -dt donor_tmp_XXXXXXXX)


    # Create the SST info file
    # This file contains SST information that is passed from the
    # donor to the joiner.
    #
    # Add more parameters to the file here as needed
    # This file has the same format as a cnf file.
    #
    sst_info_file_path="${donor_tmpdir}/${SST_INFO_FILE}"
    echo "[sst]" > "$sst_info_file_path"
    echo "binlog-name=$(basename "$WSREP_SST_OPT_BINLOG")" >> "$sst_info_file_path"
    echo "mysql-version=$MYSQL_VERSION" >> "$sst_info_file_path"

    if [ $WSREP_SST_OPT_BYPASS -eq 0 ]
    then
        usrst=0
        if [[ -z $sst_ver ]];then 
            wsrep_log_error "Upgrade joiner to 5.6.21 or higher for backup locks support"
            wsrep_log_error "The joiner is not supported for this version of donor"
            exit 93
        fi

        get_keys
        check_extra

        set +e
        if [ "$($ZFS_BIN list -t snap -r mysql)" != 'no datasets available' ]; 
        then 
            $ZFS_BIN destroy -r mysql@sst
        fi
        $MYSQL_CLIENT -u$WSREP_SST_OPT_USER -p$WSREP_SST_OPT_PSWD -BNe 'FLUSH TABLES WITH READ LOCK; \! sudo /sbin/zfs snap -r mysql@sst ; SHOW GLOBAL STATUS LIKE "wsrep_last_committed"' > ${donor_tmpdir}/seqno
        set -e

        sst_info_file_path="${donor_tmpdir}/${SST_INFO_FILE}"
        echo "galera-gtid=$(echo $WSREP_SST_OPT_GTID|cut -d: -f1):$(cat ${donor_tmpdir}/seqno|grep wsrep_last_committed|awk '{print $2}')" >> "$sst_info_file_path"

        # Before the real SST,send the sst-info
        wsrep_log_info "Streaming SST meta-info file before SST"

        FILE_TO_STREAM=$SST_INFO_FILE
        send_donor "$donor_tmpdir" "${stagemsg}-sst-info"

        set +e
        ( $0 --role sendr --address $WSREP_SST_OPT_ADDR --datadir ${DATA} \
        --defaults-file $WSREP_SST_OPT_CONF --gtid $WSREP_SST_OPT_GTID \
        2>&1 > /dev/null ) &
        set -e

        wsrep_log_info "$ZFS_BIN send process has started"
        exit 22

    else # BYPASS FOR IST

        echo "galera-gtid=$WSREP_SST_OPT_GTID" >> "$sst_info_file_path"
        wsrep_log_info "Bypassing the SST for IST"
        echo "continue" # now server can resume updating data
        echo "1" > "${donor_tmpdir}/${IST_FILE}"
        strmcmd+=" \${IST_FILE}"

        FILE_TO_STREAM=$SST_INFO_FILE
        send_donor "$donor_tmpdir" "${stagemsg}-IST"

    fi

    echo "done ${WSREP_SST_OPT_GTID}"
    wsrep_log_info "Total time on donor: $totime seconds"

elif [ "${WSREP_SST_OPT_ROLE}" = "joiner" ]
then
    stagemsg="Joiner-Recv"

    MODULE="zfs_sst"

    initialize_tmpdir
    # main temp directory for SST (non-XB) related files
    joiner_tmpdir=$(mktemp -p "${tmpdirbase}" -dt joiner_tmp_XXXXXXXX)

    rm -f "${DATA}/${IST_FILE}"

    wait_for_listen ${WSREP_SST_OPT_HOST} ${WSREP_SST_OPT_PORT:-4444} ${MODULE} &

    trap sig_joiner_cleanup HUP PIPE INT TERM

    sst_file_info_path="${joiner_tmpdir}/${SST_INFO_FILE}"

    recv_joiner "${joiner_tmpdir}" "${stagemsg}-sst-info" 10 -1

    #
    # Determine which file was received, the GTID or the SST_INFO
    #
    if [[ -r "${joiner_tmpdir}/${SST_INFO_FILE}" ]]; then
        #
        # Extract information from the sst-info file that was just received
        #
        MAGIC_FILE="${joiner_tmpdir}/${INFO_FILE}"
        echo "$(cat $sst_file_info_path|grep galera-gtid|cut -d= -f2)" > "$MAGIC_FILE"

    elif [[ -r "${joiner_tmpdir}/${INFO_FILE}" ]]; then
        #
        # For compatibility, we have received the gtid file
        #
        MAGIC_FILE="${joiner_tmpdir}/${INFO_FILE}"

    else
        wsrep_log_error "Did not receive expected file from donor: '${SST_INFO_FILE}' or '${INFO_FILE}'"
        exit 32
    fi

    if ! ps -p ${WSREP_SST_OPT_PARENT} &>/dev/null
    then
        wsrep_log_error "Parent mysqld process (PID:${WSREP_SST_OPT_PARENT}) terminated unexpectedly." 
        exit 32
    fi

    if [ ! -r "${joiner_tmpdir}/${IST_FILE}" ]
    then
        set +e
        
        if [ -d /proc/$$/fd/ ]; then
            for descriptor_path in /proc/$$/fd/*; do
                descriptor="$(basename "$descriptor_path")"
                # Don't close stdin/stderr/stdout (-gt 2)
                if [ $descriptor -gt 2 -a "$(ls -l ${descriptor_path}| cut -d'>' -f2|egrep -o '^\s+\/mysql\/'|grep -o mysql)" == 'mysql' ]; then
                    exec {descriptor}<&-
                fi
            done
        fi

        pushd "${tmpdirbase}" 1> /dev/null
        ( $0 --role recvr --address $WSREP_SST_OPT_HOST --datadir ${tmpdirbase} \
            --defaults-file $WSREP_SST_OPT_CONF --parent ${WSREP_SST_OPT_PARENT}  \
            --gtid $(cat $MAGIC_FILE) 2>&1 > /dev/null ) &
        popd 1>/dev/null
        set -e

        wsrep_log_info "SST Init complete, switching to temporary mysqld instance to unmount ZFS dataset."
        wsrep_log_info "Received UUID:SEQNO from snapshot $(cat $MAGIC_FILE)"
        exit 32

    else
        wsrep_log_info "${IST_FILE} received from donor: Running IST"
    fi

    if [[ ! -r ${MAGIC_FILE} ]];then 
        wsrep_log_error "SST magic file ${MAGIC_FILE} not found/readable"
        exit 2
    fi

    wsrep_log_info "Galera co-ords from recovery: $(cat ${MAGIC_FILE})"
    cat "${MAGIC_FILE}" # output UUID:seqno
    wsrep_log_info "Total time on joiner: $totime seconds"

elif [ "${WSREP_SST_OPT_ROLE}" = "sendr" ]
then
    wsrep_log_info "Streaming the backup to joiner at ${REMOTEIP} ${SST_PORT:-4444}"

    # Add encryption to the head of the stream (if specified)
    if [[ $encrypt -eq 1 ]]; then
        tcmd=" \$ecmd | $tcmd "
    fi

    set +e
    wsrep_log_info "Sleeping to give joiner time to setup ZFS receive"
    sleep 30
    timeit "${stagemsg}-SST" "$ZFS_BIN send -R mysql@sst | $tcmd; RC=( "\${PIPESTATUS[@]}" )"
    set -e

    if [ ${RC[0]} -ne 0 ]; then
      wsrep_log_error "$ZFS_BIN send -R mysql@sst finished with error: ${RC[0]}. "
      exit 22
    elif [[ ${RC[$(( ${#RC[@]}-1 ))]} -eq 1 ]];then 
      wsrep_log_error "$tcmd finished with error: ${RC[1]}"
      exit 22
    fi

    echo "done ${WSREP_SST_OPT_GTID}"
    wsrep_log_info "Total time on donor: $totime seconds"

elif [ "${WSREP_SST_OPT_ROLE}" = "recvr" ]
then

    stagemsg="Joiner-Recv"

    MODULE="zfs_sst"

    rm -f "${DATA}/${IST_FILE}"

    wait_for_listen ${WSREP_SST_OPT_HOST} ${WSREP_SST_OPT_PORT:-4444} ${MODULE} &

    trap sig_joiner_cleanup HUP PIPE INT TERM
    trap cleanup_joiner EXIT

    initialize_tmpdir

    sst_file_info_path="${tmpdirbase}/${SST_INFO_FILE}"

    for i in {1..120}
    do
        if ! ps -p ${WSREP_SST_OPT_PARENT} &>/dev/null
        then
            wsrep_log_info "Parent mysqld process stopped, we can safely destroy ZFS datasets." 
            break
        fi

        wsrep_log_info "Waiting for parent mysqld process to stop ..."
        sleep 1
    done

    for snap in $($ZFS_BIN list -rt snap mysql 2> /dev/null | tail -n+2 | awk '{print $1}'); do 
        $ZFS_BIN destroy -f $snap 
    done

    for dset in $(cat /proc/mounts | egrep '^mysql/' | awk '{print $1}'); do
        $ZFS_BIN destroy -f $dset
    done

    wsrep_log_info "Sleeping to give donor time to start streaming"
    sleep 15
    recv_zfs "${tmpdirbase}" "${stagemsg}-sst-info" 60 -1
    ( sudo /usr/bin/mysqld_safe ) &

    rm -f /mysql/data/gvwstate.dat /mysql/data/auto.cnf
    cat <<EOF > /mysql/data/grastate.dat
# GALERA saved state
version: 2.1
uuid:    b41e1b57-6ac9-11e8-a3ae-325813d5e270
seqno:   $(cat $sst_file_info_path|cut -d: -f2)
safe_to_bootstrap: 0

EOF

fi

exit 0