#!/bin/bash

check_port_from_badvpn_udpgw(){
    local badvpn_udpgw=$(which badvpn-udpgw)
    local cron_file="/etc/cron.d/fenixmanager"
    local ports_=($(cat "${cron_file}" | grep "/bin/badvpn-udpgw" | grep -Eo "127.0.0.1:[0-9]{1,5}" | cut -d: -f2 | xargs ))
    
    for i in "${ports_[@]}"; do
        # ! check if port is open
        netstat -lnt | grep -q ":${i} " &&{
            # ! check if port is used by badvpn-udpgw
             local process_name=$(netstat -lntup | grep ":${i}" | grep "/.*" -o)
             if [[ ! "${process_name}" == *"badvpn-udpgw"* ]]; then
                write_log_file "Port ${i} is used by ${process_name}."
                return 1
             fi
        } || {
            # ! open port
            screen -dmS "badvpn-${1}" ${badvpn_udpgw} --loglevel 0  --listen-addr 127.0.0.1:${i} --udp-mtu 1500 && {
                write_log_file "badvpn-udpgw: ${i} is open"
                # ! check if port is present in cron file
                cat "${cron_file}" | grep -q "127.0.0.1:${i}" || {
                    # ! add port to cron file
                    local str_="screen -dmS badvpn-${1} ${badvpn_udpgw} --loglevel 0  --listen-addr 127.0.0.1:${i} --udp-mtu 1500"
                    echo "@reboot root ${str_}" >> "${cron_file}"
                    service cron restart 
                    write_log_file "badvpn-udpgw: ${i} added to cron file"
                }
            } || {
                write_log_file "badvpn-udpgw: ${i} failed to open"
            }
        }
    done

}

write_to_log_file(){
    local log_file="/var/log/FenixManager/udpgw-guardian.log"
    local current_time=$(date +"%Y-%m-%d %H:%M:%S")
    local msg="${@}"
    echo "[${current_time}] ${msg}" >> "${log_file}"
}

## ARGS ##
# $1 == '1': call to check_port_from_badvpn_udpgw
# $1 == '2': view log file
main(){
    local log_file="/var/log/FenixManager/udpgw-guardian.log"
    local current_time=$(date +"%Y-%m-%d %H:%M:%S")
    local msg="${@}"
    case "${1}" in
        '1')
            check_port_from_badvpn_udpgw
            ;;
        '2')
            cat "${log_file}"
            ;;
        *)
            echo "Usage: ${0} [1|2]"
            ;;
    esac
}



main "${@}"