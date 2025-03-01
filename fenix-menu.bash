#!/bin/bash

source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/ssh-user.bash" 
source "/etc/FenixManager/funciones/color.bash"
source "/etc/FenixManager/funciones/install-pkt.bash"
source "/etc/FenixManager/funciones/cfg-pkt.bash" 
source "/etc/FenixManager/funciones/v2ray/v2ray.bash"
source "/etc/FenixManager/funciones/other-cfg.bash" 
source "/etc/FenixManager/funciones/wireguard-install.sh"

simple_text_fenix(){
    line_separator 60
    printf "${WHITE}〢 ${GREEN}%-20s ${RED}%-25s ${GREEN}%10s ${WHITE}%4s\n" "M1001-BYTE" "FENIX-MANAGER" "${version}" "〢"
    line_separator 60
        
}

show_first_panel() {
    local tmp_distro=($(lsb_release -d |cut -f2 | tr a-z A-Z))
    local distro="${tmp_distro[0]} ${tmp_distro[1]}"
    local kernel=$(uname -r | tr a-z A-Z )
    local arch=$(dpkg --print-architecture)
    
    
    local mem_total=$(free --kilo -h | awk 'NR==2{printf $2}')
    local mem_used=$(free --kilo -h | awk 'NR==2{printf $3}')
    local mem_free=$(free --kilo -h | awk 'NR==2{printf $4}')
    local mem_available=$(free --kilo -h | awk 'NR==2{printf $7}') 
    local mem_used_percent=$(free | grep Mem | awk '{print $3/$2 * 100.0}' | cut -d. -f1)
    
    local swap=$(swapon -s)
    local swap_total=$(free --kilo -h  | awk 'NR==3{printf $2}')
    local swap_used=$(free  --kilo -h  |  awk 'NR==3{printf $3}')
    local swap_free=$(free  --kilo -h  |  awk 'NR==3{printf $4}')
    
    local cpu_core=$(grep 'cpu cores' < /proc/cpuinfo | uniq | awk '{print $4}')
    local cpu_model=$(grep name < /proc/cpuinfo | uniq | awk '{ for(f=4; f<=NF; f++) { printf $f " "; } }')
    local cpu_used=$(top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}')
    
    printf "${WHITE}〢 ${WHITE}%-3s${RED}%-${#distro}s ${WHITE}%-6s${RED}%-${#arch}s ${WHITE}%-9s${RED}%-${#kernel}s${WHITE}%$(echo 60 - 19 - ${#distro} - ${#arch} - ${#kernel} | bc)s\n" "OS: " "${distro}" "ARCH: " "${arch^^}" "KERNEL: " "${kernel}" "〢"
    printf "${WHITE}〢 ${WHITE}%4s${WHITE}${RED}%-${#mem_total}s ${WHITE}%8s${RED}%-${#mem_used}s ${WHITE}%7s${RED}%-${#mem_free}s ${WHITE}%12s${RED}%-${#mem_available}s ${WHITE}%5s %$(echo 56 - 36 - ${#mem_total} - ${#mem_used} - ${#mem_free} - ${#mem_available} | bc)s\n" "RAM: " "${mem_total}" "EN USO: " "${mem_used}" "LIBRE: " "${mem_free}" "DISPONIBLE: " "${mem_available}" "%${mem_used_percent}" "〢"
    
    printf "${WHITE}〢 ${WHITE}%-5s${RED}%-${#cpu_model}s ${WHITE}%-8s${RED}%-${#cpu_core}s ${WHITE}%$(echo 58 - 11 - ${#cpu_model} - ${#cpu_core} | bc)s\n" "CPU: " "${cpu_model}" "CORES: " "${cpu_core}" '〢'
    printf "${WHITE}〢 ${WHITE}%30s${RED}%-${#cpu_used}s ${WHITE}%$(echo 59 - 30 - ${#cpu_used} | bc)s\n" "EN USO: " "% ${cpu_used}" "〢" 
    
}

show_network_stat(){
    local file_with_ip="/etc/FenixManager/ip"
    local default_iface=$(ip route | grep default | awk '{print $5}')
    local default_iface_network_stat=($(ifconfig ${default_iface} | grep -o "(.*)" ))
    local net_down_stat=${default_iface_network_stat[1]}
    local public_ip=$(cat /etc/FenixManager/ip 2>/dev/null)
    if [[ -z "${public_ip}" ]];then
        local public_ip=$(curl -s ipinfo.io/ip)
        echo "${public_ip}" > "${file_with_ip}"
    fi
    local net_down_stat="$(echo $net_down_stat | sed -e 's/^[()]//' -e 's/[()]$//')MB"
    local net_up_stat=${default_iface_network_stat[3]}
    local net_up_stat="$(echo $net_up_stat | sed -e 's/^[()]//' -e 's/[()]$//')MB"
    printf "${WHITE}〢 ${RED}%-10s ${WHITE}%-${#net_down_stat}s ${RED}%10s ${WHITE}%-${#net_up_stat}s ${RED}%12s ${WHITE}%-${#default_iface}s %$(echo 56 - 32 - ${#net_down_stat} - ${#net_up_stat} - ${#default_iface} | bc)s\n" "DESCARGA:" "${net_down_stat}" "SUBIDA:" "${net_up_stat}" "INTERFAZ:" "${default_iface}" "〢"
    printf "${WHITE}〢 ${RED}%25s ${GREEN}%-15s ${WHITE}%$(echo 60 - 40 | bc)s \n" "DIRECCION IP:" "${public_ip}" "〢"
    
}

option_menu_software () {
    clear
    local columns=$(tput cols)
    line_separator 60
    echo -e "${BLUE}〢 ───────────── 〢  ${WHITE}MENU DE PROTOCOLOS${BLUE}  〢 ───────────────── 〢"
    line_separator 60
    
    
    [[ "${hide_ports_open_services_in_protocol_menu=}" == 'false' ]] && {
        list_services_and_ports_used
        line_separator 60
    }
    tmp_array=("OPENSSH / DROPBEAR" "squid" "stunnel4" "slowdns" "shadowsocks-libev" "openvpn" "v2ray" "fenixmanager-pysocks" "wireguard" "badvpn-udpgw")
    option_menu_package "${tmp_array[@]}" ; unset tmp_array

    option_color E 'SALIR'
    option_color M 'MENU PRINCIPAL'
    
    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        printf "\33[2K\r${WHITE}[$BBLUE${prompt}${WHITE}] : " 2>/dev/null && read   option
        
        case $option in 
            1) cfg_ssh_dropbear && main ;;
            2 ) [[ ${installed_packages[*]} =~ squid ]] && cfg_squid_proxy || squid_proxy_install ;;
            3 ) [[ ${installed_packages[*]} =~ stunnel4 ]] && cfg_stunnel4 || install_stunnel4 ;;
            4 ) [[ ${installed_packages[*]} =~ slowdns ]] && cfg_slowdns || install_slowdns ;;
            5 ) [[ ${installed_packages[*]} =~ shadowsocks-libev ]] && cfg_shadowsocks || install_shadowsocks ;;
            6 ) [[ ${installed_packages[*]} =~ openvpn ]] && cfg_openvpn || install_openvpn ;;
            7) [[ ${installed_packages[*]} =~ v2ray ]] && cfg_v2ray  || des_install_v2ray_core 1 ;;
            8) [[ ${installed_packages[*]} =~ fenixmanager-pysocks ]] && cfg_python3_proxy || install_python3_proxy ;;
            9) [[ ${installed_packages[*]} =~ wireguard ]] && cfg_wireguard || installWireGuard ;;
            10) [[ ${installed_packages[*]} =~ badvpn-udpgw ]] && cfg_badvpn || install_badvpn_udpgw ;;
            "cls" | "CLS") clear && option_menu_software ;;
            [mM]) fenix  ;;
            q|Q|e|E) exit 0 ;;
            *) tput cuu1 && tput el1
        esac
    done
}

option_menu_configuration(){
    clear
    local columns=$(tput cols)
    # relaod preferences.bash
    source "/etc/FenixManager/preferences.bash"
    line_separator 60
    echo -e "${BLUE}〢 ──────────────── 〢 ${WHITE}CONFIGURACIONES${BLUE}   〢 ────────────────── 〢"
    line_separator 60
    
    option_color 1 "ADMINISTRAR HITMAN"
    option_color 2 "ADMINISTRAR FIREWALL ( UFW )"
    option_color 3 "CAMBIAR ZONA HORARIA"
    option_color 4 "ADMINISTRAR FAIL2BAN"
    option_color 5 "PRUEBA DE VELOCIDAD"
    [[ -f "/etc/block-ads-fenixmanager-actived" ]] && option_color 6 "${RED}DESACTIVAR${WHITE} BLOQUEO DE ANUNCIOS" || option_color 6 "${GREEN}ACTIVAR${WHITE} BLOQUEO DE ANUNCIOS"
    [[ "${limit_bandwidth}" == 'true' ]] && option_color 7 "${RED}DESACTIVAR${WHITE} LIMITADOR DE ANCHO DE BANDA" || option_color 7 "${GREEN}ACTIVAR${WHITE} LIMITADOR DE ANCHO DE BANDA"
    [[ "${deny_p2p_torrent}" == 'true' ]] && option_color 8 "${RED}DESBLOQUEAR ${WHITE} CONEXIONES P2P ( TORRENT )" || option_color 8 "${GREEN}BLOQUEAR ${WHITE} CONEXIONES P2P ( TORRENT )"
    option_color 9 "CAMBIAR AJUSTES DE FENIX"
    option_color M "MENU PRINCIPAL"
    option_color E "SALIR"
    
    while true;do
        #trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(printf "\33[2K\r${WHITE}[$BBLUE${prompt}${WHITE}] : ")" opt
        case $opt in
            1)  cfg_hitman ;;
            2)  cfg_firewall_ufw && fenix ;;
            3)  cfg_timezone && fenix ;;
            4)  cfg_fail2ban && fenix ;;
            5)  speedtest_ ;;
            6)  [[ -f "/etc/block-ads-fenixmanager-actived" ]] && cfg_blockads 1 || cfg_blockads 0 ;;
            7)  limit_bandwidth ;;
            8)  block_p2p_and_torrent ;;
            9)  cfg_fenix_settings ;;
            "cls" | "CLS") clear && option_menu_configuration ;;
            [mM]) fenix ;;
            q|Q|e|E) exit 0 ;;
            *) tput cuu1 && tput el1 ;;
        esac
    done
}

option_menu() {
    option_color 1 "ADMINISTRAR USUARIOS SSH"
    option_color 2 "ADMINISTRAR USUARIOS OPENVPN"
    option_color 3 'MENU DE INSTALACION'
    option_color 4 'CONFIGURACIONES'
    option_color 5 "${YELLOW}CREAR UN SUBDOMINIO GRATIS${WHITE}"
    option_color 6 "DESINSTALAR FENIX-MANAGER"
    option_color E "SALIR"

    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(printf "\33[2K\r${WHITE}[$BBLUE${prompt}${WHITE}] : ")" user_option
        
        case $user_option in
            1 )
                clo
                break
                ;;
            2 )
                clear
                package_installed "openvpn"
                if [[ $? -eq 0 ]];then
                    option_menu_ovpn
                else
                    echo -e "${RED}[!]${WHITE} OpenVPN no esta instalado"
                    sleep 2
                    main
                fi
                break
                ;;
            3 ) option_menu_software ;;
            4 ) option_menu_configuration ;;
            5 ) create_free_subdomain ;;
            6 ) uninstall_fenixmanager ;;
            "cls" | "CLS" | 'clear') clear && main ;;
            [eEqQ]) exit 0 ;;
            *)  tput cuu1 && tput el1 ;;
            esac
        
        done
}

create_free_subdomain(){
    info "Proximamente..."
}


main(){
    clear
    check_and_veriy_preferences_integrity
    local user_db="/etc/FenixManager/database/usuarios.db"
    local hidden_panel=0
    script_executed_with_root_privileges
    check_sqlite3

    simple_text_fenix

    [[ "${hide_first_panel}" == "false" ]] && {
        show_first_panel
        line_separator 60
        ((hidden_panel++))
    }
    if [[ -f "$user_db" ]];then
        [[ "${hide_second_panel}" == "false" ]] && {
            show_acc_ssh_info
            line_separator 60
            ((hidden_panel++))
        }
    fi
    [[ "${hide_third_panel}" == "false" ]] && {
        show_network_stat
        line_separator 60
        ((hidden_panel++))
    }
    [[ "${hide_ports_open_services_in_home_menu}" == 'false' ]] && {
        list_services_and_ports_used "table"
        line_separator 60
        ((hidden_panel++))
    }
    [[ "${hidden_panel}" -eq 3 && "${hidden_panel}" -eq 1 ]] && {
        line_separator 60
    }
    
    option_menu

}
main