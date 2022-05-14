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
    if [[ "${simple_ui}" == "false" ]] || [[ -z ${simple_ui} ]];then
        line_separator 85
        printf "${GREEN}〢 ─────────── 〢${WHITE}%-10s${GREEN}〢──────────〢${WHITE}%-16s${GREEN}〢─────────〢${WHITE}%${#version}s${GREEN}〢 ────────── 〢\n" "M1001-BYTE" "FENIX  MANAGER" "${version}"
        line_separator 85
    else
        line_separator 60
        printf "${WHITE}〢 ${GREEN}%-20s ${RED}%-25s ${GREEN}%10s ${WHITE}%4s\n" "M1001-BYTE" "FENIX-MANAGER" "${version}" "〢"
        line_separator 60
        
    fi
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
    
    swap=$(swapon -s)
    swap_total=$(free --kilo -h  | awk 'NR==3{printf $2}')
    swap_used=$(free  --kilo -h  |  awk 'NR==3{printf $3}')
    swap_free=$(free  --kilo -h  |  awk 'NR==3{printf $4}')
    
    cpu_core=$(grep 'cpu cores' < /proc/cpuinfo | uniq | awk '{print $4}')
    cpu_model=$(grep name < /proc/cpuinfo | uniq | awk '{ for(f=4; f<=NF; f++) { printf $f " "; } }')
    cpu_used=$(top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}')
    
    if [[ "${simple_ui}" == "false" ]] || [[ -z ${simple_ui} ]];then
        printf "${WHITE}〢 ${RED}%10s ${WHITE}%-${#distro}s ${RED}%10s ${WHITE}%${#kernel}s  ${RED}%13s ${WHITE}%${#arch}s %$((81 - 34 - ${#distro} - ${#kernel} - ${#arch} ))s\n" "DISTRO:" "$distro" "KERNEL:" "$kernel" "ARQUITECTURA:" "${arch^^}" "〢"
        printf "${WHITE}〢 ${RED}%10s ${WHITE}%-${#mem_total}s ${RED}%11s ${WHITE}%-${#mem_used}s ${RED}%11s ${WHITE}%-${#mem_free}s ${RED}%18s ${WHITE}%5s %$((81 - 57 - ${#mem_total} - ${#mem_used} - ${#mem_free} - ${#mem_disp} ))s\n" "RAM:" "$mem_total" "EN USO:" "$mem_used" "LIBRE:" "$mem_free" "DISPONIBLE:" "${mem_available}" "〢" 
        if [[ ! -z "${swap}" ]];then
            printf "${WHITE}〢 ${RED}%-8s ${WHITE}%-${#swap_total}s  ${RED}%14s ${WHITE}%-${#swap_used}s ${RED}%11s ${WHITE}%-${#swap_free}s %$((80 - 12 - 11 - ${#swap_total} - ${#swap_used} - ${#swap_free} ))s\n" "SWAP:" "$swap_total" "EN USO:" "$swap_used" "LIBRE:" "$swap_free" "〢"
        fi
        printf "${WHITE}〢${RED}%10s ${WHITE}%-${#cpu_core}s ${RED}%-7s ${WHITE}%-${#cpu_model}s ${RED}%-7s ${WHITE}%${#cpu_used}s %$(( 81 - 9 - 16 - ${#cpu_core} - ${#cpu_model} - ${#cpu_used} ))s\n" "CORES:" "$cpu_core" "MODELO:" "$cpu_model" "EN USO:" "% $cpu_used" "〢"
    else
        printf "${WHITE}〢 ${WHITE}%-3s${RED}%-${#distro}s${WHITE}%-7s${RED}%-${#arch}s ${WHITE}%-9s${RED}%-${#kernel}s${WHITE}%$(echo 60 - 19 - ${#distro} - ${#arch} - ${#kernel} | bc)s\n" "OS: " "${distro}" "ARCH: " "${arch^^}" "KERNEL: " "${kernel}" "〢"
        printf "${WHITE}〢 ${WHITE}%4s${WHITE}${RED}%-${#mem_total}s ${WHITE}%8s${RED}%-${#mem_used}s ${WHITE}%7s${RED}%-${#mem_free}s ${WHITE}%12s${RED}%-${#mem_available}s ${WHITE}%5s %$(echo 56 - 36 - ${#mem_total} - ${#mem_used} - ${#mem_free} - ${#mem_available} | bc)s\n" "RAM: " "${mem_total}" "EN USO: " "${mem_used}" "LIBRE: " "${mem_free}" "DISPONIBLE: " "${mem_available}" "%${mem_used_percent}" "〢"
        
        printf "${WHITE}〢 ${WHITE}%-5s${RED}%-${#cpu_model}s ${WHITE}%-8s${RED}%-${#cpu_core}s ${WHITE}%$(echo 58 - 11 - ${#cpu_model} - ${#cpu_core} | bc)s\n" "CPU: " "${cpu_model}" "CORES: " "${cpu_core}" '〢'
        printf "${WHITE}〢 ${WHITE}%30s${RED}%-${#cpu_used}s ${WHITE}%$(echo 59 - 30 - ${#cpu_used} | bc)s\n" "EN USO: " "% ${cpu_used}" "〢"
        
    fi

    
    
}

show_network_stat(){
    local file_with_ip="/etc/FenixManager/ip"
    local default_iface=$(ip route | grep default | awk '{print $5}')
    local default_iface_network_stat=($(ifconfig ${default_iface} | grep -o "(.*)" ))
    local net_down_stat=${default_iface_network_stat[1]}
    local public_ip=$(cat /etc/FenixManager/ip 2>/dev/null)
    if [[ -z "${public_ip}" ]];then
        local public_ip=$(curl -s ipconfig.io/ip)
        echo "${public_ip}" > "${file_with_ip}"
    fi
    local net_down_stat="$(echo $net_down_stat | sed -e 's/^[()]//' -e 's/[()]$//')MB"
    local net_up_stat=${default_iface_network_stat[3]}
    local net_up_stat="$(echo $net_up_stat | sed -e 's/^[()]//' -e 's/[()]$//')MB"
    [[ "${simple_ui}" == "false" ]] && {
        printf "${WHITE}〢 ${RED}%-9s ${WHITE}%-15s ${RED}%-7s ${WHITE} %-15s ${RED}%-9s ${WHITE}%-${#default_iface}s ${GREEN}%${#public_ip}s ${WHITE}%$(echo 81 - 14 - 15 - 7 - 15 - 9 - ${#default_iface} - ${#public_ip} | bc)s〢\n" "DESCARGA:" "$net_down_stat MB" "SUBIDA:" "$net_up_stat MB" "INTERFAZ:" "${default_iface}" "${public_ip}"
    } || {
        printf "${WHITE}〢 ${RED}%-10s ${WHITE}%-${#net_down_stat}s ${RED}%10s ${WHITE}%-${#net_up_stat}s ${RED}%12s ${WHITE}%-${#default_iface}s %$(echo 56 - 32 - ${#net_down_stat} - ${#net_up_stat} - ${#default_iface} | bc)s\n" "DESCARGA:" "${net_down_stat}" "SUBIDA:" "${net_up_stat}" "INTERFAZ:" "${default_iface}" "〢"
        printf "${WHITE}〢 ${RED}%25s ${GREEN}%-15s ${WHITE}%$(echo 60 - 40 | bc)s \n" "DIRECCION IP:" "${public_ip}" "〢"
    }
}

option_menu_software () {
    clear
    local columns=$(tput cols)
    [[ "${simple_ui}" == "false" ]] && {
        line_separator 85
        echo -e "${BLUE}〢───────────────────────────〢  ${WHITE}MENU DE PROTOCOLOS${BLUE}   〢───────────────────────────────〢"
        line_separator 85
    } || {
        line_separator 60
        echo -e "${BLUE}〢───────────────〢  ${WHITE}MENU DE PROTOCOLOS${BLUE}   〢──────────────────〢"
        line_separator 60
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
        printf "\33[2K\r${WHITE}[$BBLUE${prompt}${WHITE}] : " 2>/dev/null && read   option
        
        case $option in 
            0) cfg_ssh_dropbear && main ;;
            1 ) [[ ${installed_packages[*]} =~ squid ]] && cfg_squid_proxy || squid_proxy_install ;;
            2 ) [[ ${installed_packages[*]} =~ stunnel4 ]] && cfg_stunnel4 || install_stunnel4 ;;
            3 ) [[ ${installed_packages[*]} =~ slowdns ]] && cfg_slowdns || install_slowdns ;;
            4 ) [[ ${installed_packages[*]} =~ shadowsocks-libev ]] && cfg_shadowsocks || install_shadowsocks ;;
            5 ) [[ ${installed_packages[*]} =~ openvpn ]] && cgf_openvpn || install_openvpn ;;
            6) [[ ${installed_packages[*]} =~ v2ray ]] && cfg_v2ray  || des_install_v2ray_core 1 ;;
            7) [[ ${installed_packages[*]} =~ python3-proxy ]] && cfg_python3_proxy || install_python3_proxy ;;
            
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
    [[ "${simple_ui}" == 'false' ]] && {
        line_separator 85
        echo -e "${BLUE}〢───────────────────────────〢  ${WHITE}CONFIGURACIONES${BLUE}   〢──────────────────────────────────〢"
        line_separator 85
    } || {
        line_separator 60
        echo -e "${BLUE}〢─────────────────〢  ${WHITE}CONFIGURACIONES${BLUE}   〢───────────────────〢"
        line_separator 60
    }
    
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
    option_color 6 "${GREEN}BUSCAR ACTUALIZACIONES${WHITE}"
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
            3 ) option_menu_configuration ;;
            4 ) option_menu_configuration ;;
            5 ) create_free_subdomain ;;
            6 )
                {
                    local remote_version=$(curl -s https://raw.githubusercontent.com/M1001-byte/FenixManager/master/version)
                    local current_version=$(cat /etc/FenixManager/version)
                    [[ -z "${current_version}" ]] && error "Fallo al obtener la version local."
                    [[ -z "${remote_version}" ]] && error "Fallo al obtener la version remota. Comprueba tu conexion a internet."

                    if [[ "${remote_version}" == "${current_version}" ]];then
                        info "Tu version de Fenix Manager es la mas reciente"
                    else
                        info "Hay una ${GREEN}nueva version${WHITE} de Fenix Manager disponible"
                        info "Tu version: ${current_version}"
                        info "Nueva version: ${remote_version}"
                        read -p "[*] Deseas actualizar? [Y/n] " opt
                        case $opt in
                            y|Y|S|s)
                                info "Actualizando..."
                                [[ -d "/tmp/FenixManager" ]] && rm -rf /tmp/FenixManager
                                git clone "https://github.com/M1001-byte/FenixManager.git" /tmp/FenixManager && {
                                    rsync -av --progress /tmp/FenixManager/ /etc/FenixManager/ --exclude .git
                                    local fenix_bash_files=$(find /etc/FenixManager/ -name "*.bash")
                                    for file in $fenix_bash_files; do chmod 777 $file &>/dev/null ; done
                                    info "Fenix Manager se actualizo correctamente"
                                    exit 0
                                } || {
                                    error "Ocurrio un error. La actualizacion no pudo ser completada."
                                    exit $?
                                }
                                ;;
                            *)
                            info "Fenix Manager no se actualizo"
                            ;;
                        esac
                    fi
                }
                    ;;
            "cls" | "CLS") clear && main ;;
            [eEqQ]) exit 0 ;;
            *)  tput cuu1 && tput el1 ;;
            esac
        
        done
}

create_free_subdomain(){
    info "No es posible crear un subdominio gratis desde Fenix."
    info "Lista de sitios que ${GREEN}SI${WHITE} lo permiten:"
    local sites=("www.jagoanssh.com" "serverssh.net" "www.fastssh.com" "hidessh.com" "www.pointdns.net" "www.premiumssh.net" "opentunnel.net")
    local sites_day_available=("15 dias" "30 dias" "3 meses" "30 dias" "30 dias" "30 dias" "10 dias")
    for ((i=0;i<${#sites[@]};i++));do
        local site=${sites[$i]}
        local days_=${sites_day_available[$i]}
        [[ "${simple_ui}" == "false" ]] && {
            printf "${WHITE}〢  ${GREEN}%-${#i}s  ${YELLOW}( %${#days_}s )  ${WHITE}%$(echo 87 - ${#site} - ${#days_} - 7| bc)s\n" "${site}" "${days_}" "〢"
        } || {
            printf "${WHITE}〢  ${GREEN}%-${#i}s  ${YELLOW}( %${#days_}s )  ${WHITE}%$(echo 60 - ${#site} - ${#days_} - 7| bc)s\n" "${site}" "${days_}" "〢"
        }
        
    done
}


main(){
    clear
    check_and_veriy_preferences_integrity
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
        [[ "${simple_ui}" == "false" ]] && line_separator 85 || line_separator 60
        ((hidden_panel++))
    }
    if [[ -f "$user_db" ]];then
        [[ "${hide_second_panel}" == "false" ]] && {
            show_acc_ssh_info
            [[ "${simple_ui}" == "false" ]] && line_separator 85 || line_separator 60
            ((hidden_panel++))
        }
    fi
    [[ "${hide_third_panel}" == "false" ]] && {
        show_network_stat
        [[ "${simple_ui}" == "false" ]] && line_separator 85 || line_separator 60
        ((hidden_panel++))
    }
    [[ "${hide_ports_open_services_in_home_menu}" == 'false' ]] && {
        list_services_and_ports_used "table"
        [[ "${simple_ui}" == "false" ]] && line_separator 85 || line_separator 60
        ((hidden_panel++))
    }
    [[ "${hidden_panel}" -eq 3 && "${hidden_panel}" -eq 1 ]] && {
        [[ "${simple_ui}" == "false" ]] && line_separator 85 || line_separator 60
    }
    
    option_menu

}
main