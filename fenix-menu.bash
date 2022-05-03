#!/usr/bin/bash

source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/ssh-user.bash"
source "/etc/FenixManager/funciones/color.bash"
source "/etc/FenixManager/funciones/install-pkt.bash"
source "/etc/FenixManager/funciones/cfg-pkt.bash"
source "/etc/FenixManager/funciones/v2ray/v2ray.bash"
source "/etc/FenixManager/funciones/other-cfg.bash"

source "/etc/FenixManager/preferences.bash"


simple_text_fenix(){
    [[ $columns -le 78 ]] && {
        line_separator 72
        printf "${GREEN}〢 ───── 〢${WHITE}%-10s${GREEN}〢 ────── 〢${WHITE}%-14s${GREEN}〢 ────── 〢${WHITE}%${#version}s${GREEN}〢 ──── 〢\n" "M1001-BYTE" "FENIX  MANAGER" "${version}"
        line_separator 72
    } || {
        line_separator 85
        printf "${GREEN}〢 ─────────── 〢${WHITE}%-10s${GREEN}〢──────────〢${WHITE}%-14s${GREEN}〢─────────〢${WHITE}%${#version}s${GREEN}〢 ────────── 〢\n" "M1001-BYTE" "FENIX  MANAGER" "${version}"
        line_separator 85
    }    
}

show_first_panel() {
    local tmp_distro=($(lsb_release -d |cut -f2 | tr a-z A-Z))
    local distro="${tmp_distro[0]} ${tmp_distro[1]}"
    kernel=$(uname -r | tr a-z A-Z )
    arch=$(dpkg --print-architecture)
    
    
    local mem_total=$(free --kilo -h | awk 'NR==2{printf $2}')
    local mem_used=$(free --kilo -h | awk 'NR==2{printf $3}')
    local mem_free=$(free --kilo -h | awk 'NR==2{printf $4}')
    local mem_disp=$(free --kilo -h | awk 'NR==2{printf $7}') 
    
    swap=$(swapon -s)
    swap_total=$(free --kilo -h  | awk 'NR==3{printf $2}')
    swap_used=$(free  --kilo -h  |  awk 'NR==3{printf $3}')
    swap_free=$(free  --kilo -h  |  awk 'NR==3{printf $4}')
    
    cpu_core=$(grep 'cpu cores' < /proc/cpuinfo | uniq | awk '{print $4}')
    cpu_model=$(grep name < /proc/cpuinfo | uniq | awk '{ for(f=4; f<=NF; f++) { printf $f " "; } }')
    cpu_used=$(top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}')
    
    [[ $columns -le 78 ]] && {
        printf "${WHITE}〢 ${RED}%-7s ${WHITE}%-${#distro}s ${RED}%-7s ${WHITE}%-${#kernel}s ${RED}%13s ${WHITE}%-${#arch}s %$(echo 68 - 27 - ${#distro} - ${#kernel} - ${#arch} | bc)s\n" "DISTRO:" "$distro" "KERNEL:" "$kernel" "ARQUITECTURA:" "${arch^^}" "〢"
        printf "${WHITE}〢 ${RED}%-4s ${WHITE}%-${#mem_total}s ${RED}%11s ${WHITE}%-${#mem_used}s ${RED}%11s ${WHITE}%-${#mem_free}s ${RED}%18s ${WHITE}%5s %$(echo 68 - 4 - 11 - 11 - 18  - 3 - ${#mem_total} - ${#mem_used} - ${#mem_free} - ${#mem_disp} | bc)s\n" "RAM:" "$mem_total" "EN USO:" "$mem_used" "LIBRE:" "$mem_free" "DISPONIBLE:" "${mem_disp}" "〢" 
        if [[ ! -z "${swap}" ]];then
            printf "${WHITE}〢 ${RED}%-8s ${WHITE}%-${#swap_total}s  ${RED}%14s ${WHITE}%-${#swap_used}s ${RED}%11s ${WHITE}%-${#swap_free}s %$(echo 68 - 12 - 11 - ${#swap_total} - ${#swap_used} - ${#swap_free} | bc)s\n" "SWAP:" "$swap_total" "EN USO:" "$swap_used" "LIBRE:" "$swap_free" "〢"
        fi
        printf "${WHITE}〢 ${RED}%-6s ${WHITE}%-${#cpu_core}s ${RED}%-7s ${WHITE}%-${#cpu_model}s ${RED}%-7s ${WHITE}%${#cpu_used}s %$(echo 68 - 6 - 16 - ${#cpu_core} - ${#cpu_model} - ${#cpu_used} | bc)s\n" "CORES:" "$cpu_core" "MODELO:" "$cpu_model" "EN USO:" "% $cpu_used" "〢"
    } || {
        printf "${WHITE}〢 ${RED}%-7s ${WHITE}%-${#distro}s ${RED}%-7s ${WHITE}%-${#kernel}s ${RED}%13s ${WHITE}%-${#arch}s %$(echo 83 - 27 - ${#distro} - ${#kernel} - ${#arch} | bc)s\n" "DISTRO:" "$distro" "KERNEL:" "$kernel" "ARQUITECTURA:" "${arch^^}" "〢"
        printf "${WHITE}〢 ${RED}%-12s ${WHITE}%-${#mem_total}s ${RED}%11s ${WHITE}%-${#mem_used}s ${RED}%11s ${WHITE}%-${#mem_free}s ${RED}%18s ${WHITE}%${#mem_disp}s %$(echo 70 - 12 - 11 - 18 - ${#mem_total} - ${#mem_used} - ${#mem_free} - ${#mem_disp} | bc)s\n" "MEMORIA RAM:" "$mem_total" "EN USO:" "$mem_used" "LIBRE:" "$mem_free" "DISPONIBLE:" "${mem_disp}" "〢" 
        if [[ ! -z "${swap}" ]];then
            local length_third_line=$(echo 72 - 12 - 11 - ${#swap_total} - ${#swap_used} - ${#swap_free} | bc)
            printf "${WHITE}〢 ${RED}%-8s ${WHITE}%-${#swap_total}s  ${RED}%14s ${WHITE}%-${#swap_used}s ${RED}%11s ${WHITE}%-${#swap_free}s %${length_third_line}s\n" "SWAP:" "$swap_total" "EN USO:" "$swap_used" "LIBRE:" "$swap_free" "〢"
        fi
        printf "${WHITE}〢 ${RED}%-10s ${WHITE}%-${#cpu_core}s ${RED}%-8s ${WHITE}%-${#cpu_model}s ${RED}%-8s ${WHITE}%-${#cpu_used}s %$(echo 78 - 12 - 11 - ${#cpu_core} - ${#cpu_model} - ${#cpu_used} | bc)s\n" "CPU-CORES:" "$cpu_core" "MODELO:" "$cpu_model" "EN USO:" "% $cpu_used" "〢"
    }
    
    
}

show_acc_ssh_info(){
    local user_db="/etc/FenixManager/database/usuarios.db"
    local get_total_users=$(sqlite3 "$user_db" "SELECT COUNT(*) FROM ssh")
    local users_=$(sqlite3 "$user_db" "SELECT nombre FROM ssh")
    local count_=0
    for i in ${users_[@]};do
        number_session=$(ps auxwww | grep 'sshd:' | awk '{print $1 }' | grep -w -c "$user")
        if [[ "${number_session}" -ne 0 ]];then count_=$((count_+1)) ; fi
    done
    local offline_users=$(echo ${get_total_users} - ${count_} | bc)
    [[ $columns -le 78 ]] && {
        printf "${WHITE}〢 %15s ${YELLOW}%-${#get_total_users}s ${WHITE} %-12s ${GREEN}%-${#count_}s ${WHITE}%15s ${RED}%-${#count_}s ${WHITE}%$(echo 51 - 30 - 12  - ${#get_total_users} - ${#count_} - ${#offline_users} | bc)s 〢\n" "USUARIOS-SSH:" "[ ${get_total_users} ]" "CONECTADOS:" "[ ${count_} ]" "DESCONECTADOS:" "[ ${offline_users} ]" 
    } || {
        printf "${WHITE}〢 %20s ${YELLOW}%-${#get_total_users}s ${WHITE} %-12s ${GREEN}%-${#count_}s ${WHITE}%16s ${RED}%-${#count_}s ${WHITE}%$(echo 66 - 20 - 12 - 16 - ${#get_total_users} - ${#count_} - ${#offline_users} | bc)s 〢\n" "USUARIOS-SSH:" "[ ${get_total_users} ]" "CONECTADOS:" "[ ${count_} ]" "DESCONECTADOS:" "[ ${offline_users} ]" 
    }
}

show_network_stat(){
    local file_with_ip="/etc/FenixManager/ip"
    local default_iface=$(ip route | grep default | awk '{print $5}')
    local default_iface_network_stat=($(ifconfig ${default_iface} | grep -o "(.*)" ))
    local net_down_stat=${default_iface_network_stat[1]}
    local public_ip=$(cat /etc/FenixManager/ip 2>/dev/null)
    net_down_stat=$(echo $net_down_stat | sed -e 's/^[()]//' -e 's/[()]$//')
    local net_up_stat=${default_iface_network_stat[3]}
    net_up_stat=$(echo $net_up_stat | sed -e 's/^[()]//' -e 's/[()]$//')
    [[ $columns -le 78 ]] && {
        printf "${WHITE}〢 ${RED}%-9s ${WHITE}%-15s ${RED}%-7s ${WHITE} %-15s ${RED}%-9s ${WHITE}%-${#default_iface}s ${WHITE}%$(echo 65 - 10 - 15 - 7 - 15 - 9 - ${#default_iface} | bc)s〢\n" "DESCARGA:" "$net_down_stat MB" "SUBIDA:" "$net_up_stat MB" "INTERFAZ:" "${default_iface}"
        printf "${WHITE}〢 ${GREEN}%40s ${WHITE}%33s\n" "${public_ip}" '〢'
    } || {
        printf "${WHITE}〢 ${RED}%-9s ${WHITE}%-15s ${RED}%-7s ${WHITE} %-15s ${RED}%-9s ${WHITE}%-${#default_iface}s ${GREEN}%${#public_ip}s ${WHITE}%$(echo 78 - 9 - 15 - 7 - 15 - 9 - ${#default_iface} - ${#public_ip} | bc)s〢\n" "DESCARGA:" "$net_down_stat MB" "SUBIDA:" "$net_up_stat MB" "INTERFAZ:" "${default_iface}" "${public_ip}"
    }
}

option_menu_software () {
    clear
    local columns=$(tput cols)
    [[ $columns -le 78 ]] && {
        line_separator 72
        echo -e "${BLUE}〢 ───────────────────── 〢  ${WHITE}MENU DE PROTOCOLOS${BLUE}   〢 ──────────────────── 〢"
        line_separator 72
    } || {
        line_separator 85
        echo -e "${BLUE}〢 ────────────────────────── 〢  ${WHITE}MENU DE PROTOCOLOS${BLUE}   〢 ────────────────────────────── 〢"
        line_separator 85
    }
    [[ "${hide_ports_open_services_in_protocol_menu=}" == 'false' ]] && {
        list_services_and_ports_used "table"
        [[ $columns -le 78 ]] && line_separator 72 || line_separator 85
    }
    # list_services_and_ports_used 
    # line_separator 85
    option_color 0 'CONFIGURAR OPENSSH / DROPBEAR'
    tmp_array=( "squid" "stunnel4" "slowdns" "shadowsocks-libev" "openvpn" "v2ray" "python3-proxy")
    option_menu_package "${tmp_array[@]}" ; unset tmp_array

    option_color E 'SALIR'
    option_color M 'MENU PRINCIPAL'

    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[${BBLUE}${prompt}${WHITE}")] : " option
        
        case $option in 
            0) # OPENSSH/DROPBEAR
                cfg_ssh_dropbear
                main
                ;;
            1 ) # squid proxy
                if [[ ${installed_packages[*]} =~ squid ]];then
                    cfg_squid_proxy
                else
                    squid_proxy_install
                fi
                main
                ;;
            2 ) # stunnel4
                if [[ ${installed_packages[*]} =~ stunnel4 ]];then
                    cfg_stunnel4
                else
                    install_stunnel4
                fi
                main
                ;;
            3 ) #slowdns
                if [[ ${installed_packages[*]} =~ slowdns ]];then
                    cfg_slowdns
                else
                    install_slowdns
                fi
                main
                ;;
            4 ) #shadowsocks-libev
                if [[ ${installed_packages[*]} =~ shadowsocks-libev ]];then
                    cfg_shadowsocks
                else
                    install_shadowsocks
                fi
                main
                ;;
            5 ) #openvpn
                if [[ ${installed_packages[*]} =~ openvpn ]];then
                    cgf_openvpn
                else
                    install_openvpn
                fi
                main
                
                ;;
            6) # v2ray
                if [[ ${installed_packages[*]} =~ v2ray ]];then
                    cfg_v2ray
                else
                    des_install_v2ray_core 1
                fi
                main
                ;;
            
            7) # python3-proxy
                if [[ ${installed_packages[*]} =~ python3-proxy ]];then
                    cfg_python3_proxy
                else
                    install_python3_proxy
                fi
                main
                ;;
            "cls" | "CLS")
                clear
                option_menu_software
                ;;
            [mM])
                fenix 
                ;;
            q|Q|e|E)
                exit 0
                ;;
            *)
                continue
                ;;
            
        esac
    done
}

option_menu_configuration(){
    clear
    local columns=$(tput cols)
    [[ $columns -le 78 ]] && {
        line_separator 72
        echo -e "${BLUE}〢 ────────────────────── 〢  ${WHITE}CONFIGURACIONES${BLUE}   〢 ────────────────────── 〢"
        line_separator 72
    } || {
        line_separator 85
        echo -e "${BLUE}〢 ────────────────────────── 〢  ${WHITE}CONFIGURACIONES${BLUE}   〢 ───────────────────────────────── 〢"
        line_separator 85
    }
    option_color 1 "ADMINISTRAR HITMAN"
    option_color 2 "ADMINISTRAR FIREWALL ( UFW )"
    option_color 3 "CAMBIAR ZONA HORARIA"
    option_color 4 "ADMINISTRAR FAIL2BAN"
    option_color 5 "PRUEBA DE VELOCIDAD"
    [[ -f "/etc/block-ads-fenixmanager-actived" ]] && option_color 6 "${RED}DESACTIVAR${WHITE} BLOQUEO DE ANUNCIOS" || option_color 6 "${GREEN}ACTIVAR${WHITE} BLOQUEO DE ANUNCIOS"
    [[ "${limit_bandwidth}" == 'true' ]] && option_color 7 "${RED}DESACTIVAR${WHITE} LIMITADOR DE ANCHO DE BANDA" || option_color 7 "${GREEN}ACTIVAR${WHITE} LIMITADOR DE ANCHO DE BANDA"
    option_color 8 "CAMBIAR AJUSTES DE FENIX"
    option_color M "MENU PRINCIPAL"
    option_color E "SALIR"
    
    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " opt
        case $opt in
            1) # ADMINISTRAR HITMAN
                cfg_hitman
                ;;
            2) # ADMINISTAR FIREWALL ( UFW )
                cfg_firewall_ufw
                fenix
                ;;
            3) # CAMBIAR ZONA HORARIAS
                cfg_timezone
                fenix
                ;;
            4) # ADMINISTRAR FAIL2BAN
                cfg_fail2ban
                fenix
                ;;
            5) # SPEEDTEST
                speedtest_
                ;;
            6) # BLOQUEAR ANUNCIOS  
                [[ -f "/etc/block-ads-fenixmanager-actived" ]] && cfg_blockads 1 || cfg_blockads 0
                ;;
            7) # LIMIT BANDWIDTH
                limit_bandwidth
                ;;
            8) # CAMBIAR AJUSTES DE FENIX
                cfg_fenix_settings
                ;;
            "cls" | "CLS")
                clear
                option_menu_configuration
                ;;
            [mM])
                fenix
                ;;
            q|Q|e|E)
                exit 0
                ;;
            *)
                continue
                ;;
        esac
    done
}

option_menu() {

    option_color 1 "ADMINISTRAR USUARIOS SSH"
    option_color 2 "ADMINISTRAR USUARIOS OPENVPN"
    option_color 3 'MENU DE INSTALACION'
    option_color 4 'CONFIGURACIONES'
    option_color 5 "${YELLOW}CREAR UN SUBDOMINIO GRATIS${WHITE}"
    option_color E "SALIR"

    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " user_option
        case $user_option in
            1 )
                clear
                list_user
                option_menu_ssh
                break
                ;;
            2 )
                clear
                package_installed "openvpn"
                if [[ $? -eq 0 ]];then
                    list_users_ovpn
                    option_menu_ovpn
                else
                    echo -e "${RED}[!]${WHITE} OpenVPN no esta instalado"
                    sleep 2
                    main
                fi
                break
                ;;
            3 )
                option_menu_software
                ;;
            3 )
                option_menu_configuration
                ;;
            4 )
                option_menu_configuration
                ;;
            5 )
                create_free_subdomain
                ;;
            
            "cls" | "CLS")
                clear
                main
                ;;
            [eEqQ])
                exit 0
                ;;
            *) 
                continue
                ;;
            esac
        unset user_option
        done
}

create_free_subdomain(){
    info "Actualmente, no es posible crear un subdominio gratis desde Fenix."
    info "Pero tranquilo, aqui te dejo una lista de sitios que ${GREEN}SI${WHITE} lo permiten:"
    local sites=("www.jagoanssh.com" "serverssh.net" "www.fastssh.com" "hidessh.com" "www.pointdns.net" "www.premiumssh.net" "opentunnel.net")
    local sites_day_available=("15 dias" "30 dias" "3 meses" "30 dias" "30 dias" "30 dias" "10 dias")
    for ((i=0;i<${#sites[@]};i++));do
        local site=${sites[$i]}
        local days_=${sites_day_available[$i]}
        [[ $columns -le 78 ]] && {
            printf "${WHITE}〢  ${GREEN}%-${#i}s  ${YELLOW}( %${#days_}s )  ${WHITE}%$(echo 73 - ${#site} - ${#days_} - 7| bc)s\n" "${site}" "${days_}" "〢"
        } || {
            printf "${WHITE}〢  ${GREEN}%-${#i}s  ${YELLOW}( %${#days_}s )  ${WHITE}%$(echo 87 - ${#site} - ${#days_} - 7| bc)s\n" "${site}" "${days_}" "〢"
        }
        
    done
}

main(){
    clear
    local user_db="/etc/FenixManager/database/usuarios.db"
    local hidden_panel=0
    script_executed_with_root_privileges
    check_sqlite3
    
    [[ "${show_fenix_banner}" == "false" ]] && {
        simple_text_fenix
    } || {
        print_banner
        }
    [[ "${hide_first_panel}" == "false" ]] && {
        show_first_panel
        [[ $columns -le 78 ]] && line_separator 72 || line_separator 85
        ((hidden_panel++))
    }
    if [[ -f "$user_db" ]];then
        [[ "${hide_second_panel}" == "false" ]] && {
            show_acc_ssh_info
            [[ $columns -le 78 ]] && line_separator 72 || line_separator 85
            ((hidden_panel++))
        }
    fi
    [[ "${hide_third_panel}" == "false" ]] && {
        show_network_stat
        [[ $columns -le 78 ]] && line_separator 72 || line_separator 85
        ((hidden_panel++))
    }
    [[ "${hide_ports_open_services_in_home_menu}" == 'false' ]] && {
        list_services_and_ports_used "table"
        [[ $columns -le 78 ]] && line_separator 72 || line_separator 85
        ((hidden_panel++))
    }
    [[ "${hidden_panel}" -eq 3 && "${hidden_panel}" -eq 1 ]] && {
        [[ $columns -le 78 ]] && line_separator 72 || line_separator 85
    }
    option_menu

}
main