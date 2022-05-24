#!/bin/bash

source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/color.bash" 2>/dev/null
source "/etc/FenixManager/funciones/hitman.bash"
source "/etc/FenixManager/preferences.bash" 2>/dev/null

script_executed_with_root_privileges


deny_allow_port_ufw_input(){ # *OPERATION = DENY OR ALLOW
    local operation str_show
    local operation="$1"
    [ "${operation}" == "ALLOW" ] && str_show="permitir" || str_show="bloquear"

    info "Para ${str_show} un puerto, introduzca el número del puerto seguido de /[protocolo]."
    info "Ejemplo: 80/tcp 443/udp 2222/all"
    while true;do
    read -r -p "[*] Introduzca los puertos que desa ${str_show} ( separados por espacio ): " ports_array
    if [ -z "${ports_array}" ];then continue ; fi
        for ports_str in "${ports_array[@]}";do
            IFS='/' read -r -a array <<< "${ports_str}"
            [ ${#array[@]} -ne 2 ] && continue
            local puerto="${array[0]}"
            local protocolo="${array[1]}"

            if [[ "${puerto}" =~ ^[0-9]+$ ]];then
                if [[ "${protocolo}" =~ ^(tcp|udp|all)$ ]];then
                    bar "ufw ${operation} ${puerto}/${protocolo}"
                    sleep 3
                    cfg_firewall_ufw
                else
                    error "¿ ${YELLOW}${protocolo}${WHITE} es un nuevo protocolo ? Solo se permiten tcp, udp o all(todos los anteriores)."
                fi
            else
                error "El puerto ${array[0]} no es válido."
            fi
        done
    done
}

cfg_hitman(){
    local fenixmanager_crontab_file="/etc/cron.d/fenixmanager"
    local hitman_logfile="/var/log/FenixManager/hitman.log"
    local minutes_=$(grep -E ".*/[0-9]{1,3}" "${fenixmanager_crontab_file}" -o | awk '{split($0,a,"/"); print a[2]}')
        
    clear
    echo -e "${BLUE}〢──────────────────〢 ${WHITE}CONFIGURANDO HITMAN ${BLUE}〢─────────────────〢"
    show_info(){
        # 69
        # 67
        local cron_is_running=$(ps -ef | grep -v grep | grep cron | wc -l)
        # ! CHECK IF CRON IS RUNNING
        if [ $cron_is_running -eq 0 ]; then
            printf "${WHITE}〢%4s : ${RED}%46s ${WHITE}%10s\n" "CRON" "[ DETENIDO ] NO SE PUEDE EJECUTAR EL SCRIPT DE HITMAN." "〢"
            bar "systemctl start cron"
            if [ $? -eq 0 ]; then info "SE HA INICIADO EL SERVICIO CRON." ; sleep 4 && cfg_hitman ; else error "NO SE HA INICIADO EL SERVICIO CRON. CONTACTESE CON EL ADMINISTRADOR." ; exit $? ; fi
        else
            printf "${WHITE}〢%4s : ${GREEN}%16s ${WHITE}%39s\n" "CRON" "[ EJECUTANDOSE ]" "〢"
        fi
        # ! CHECK IF CRON-FILE EXISTS
        if [ ! -f "$fenixmanager_crontab_file" ]; then
            error "NO SE HA ENCONTRADO EL ARCHIVO CRONTAB DE FENIXMANAGER."
            sleep 3
            add_cront_job_for_hitman
        else
            printf "${WHITE}〢%9s : ${GREEN}%${#fenixmanager_crontab_file}s ${WHITE}%$((60 - 10 - ${#fenixmanager_crontab_file}))s\n" "CRON-FILE" "${fenixmanager_crontab_file}" "〢"
        fi
        printf "${WHITE}〢%15s : ${GREEN}%${#hitman_logfile}s ${WHITE}%$((60 - 16 - ${#hitman_logfile}))s\n" "HITMAN-LOG-FILE" "${hitman_logfile}" "〢"
        line_separator 60
        local info_hour_del_expired_acc="DIARIAMENTE, A LAS 00:00: HITMAN ELIMINARA LAS CUENTAS EXPIRADAS."
        printf "${WHITE}${YELLOW}%${#info_hour_del_expired_acc}s ${WHITE}%3s\n" "${info_hour_del_expired_acc}"
        local info_check_acc_exceded_limit="CADA ${minutes_} MINUTOS,HITMAN COMPROBARA SI HAY CUENTAS CON EXCEDENTE DE LIMITE DE CONEXIONES."
        printf "${WHITE}${YELLOW}%${#info_check_acc_exceded_limit}s ${WHITE}%3s\n" "${info_check_acc_exceded_limit}" ""
        line_separator 60
    }
    show_info
    option_color 1 "VER REGISTRO DE HITMAN"
    option_color 2 "CAMBIAR EL TIEMPO DE COMPROBACION; USUARIOS CON EXCEDENTE DE CONEXIONES"
    option_color M "MENÚ PRINCIPAL"
    option_color E "SALIR"
    
    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " opt
        case $opt in
            1) # VER REGISTRO DE HITMAN
                clear
                [[ -f "${hitman_logfile}" ]] && {
                    [[ "${simple_ui}" == "true" ]] && nano "${hitman_logfile}" ; cfg_hitman || less "${hitman_logfile}"
                } || info "No hay registro de hitman."
                ;;
            2) # CAMBIAR EL TIEMPO DE EJECUCIÓN; USUARIOS CON EXCEDENTE DE CONEXIONES
                {   
                    info "Cada cuanto se ejecutará el script de HITMAN (en minutos), para comprobar si hay cuentas con excedente de conexiones."
                    while true;do
                        read -r -p "[*] Tiempo de ejecución (minutos): " time_to_run
                        # time_to_run es mayor que 0 y menor que 60
                        if [ $time_to_run -gt 0 ] && [ $time_to_run -lt 60 ]; then
                            break
                        else
                            error "El tiempo de ejecución debe ser mayor que 0 y menor que 60."
                            info "O presione [CTRL+C] para salir y utilizar el valor por defecto ( 15 minutos )."
                        fi
                    done
                    local line_number=$(grep "/home/mathiue/FenixManager/funciones/hitman.bash 2" ${fenixmanager_crontab_file} --line-number -o | awk '{split($0,a,":"); print a[1]}')
                    local minutes_=$(grep -E ".*/[1-9]{1,2}" "${fenixmanager_crontab_file}" -o | awk '{split($0,a,"/"); print a[2]}')
                    sed -i "${line_number}s/${minutes_}/${time_to_run}/" "${fenixmanager_crontab_file}"
                    if [ $? -eq 0 ]; then
                        info "El tiempo de ejecución de HITMAN ha sido cambiado a ${time_to_run} minutos."
                        bar "systemctl restart cron"
                        sleep 3
                        cfg_hitman
                    else
                        error "No se ha podido cambiar el tiempo de ejecución de HITMAN."
                        exit $?
                    fi
                    
                }
                ;;
            "cls" | "CLS")
                clear
                cfg_hitman
                ;;
            [Mm])
                fenix
                ;;
            q|Q|e|E)
                exit 0
                ;;
            esac
        done
}

cfg_firewall_ufw(){
    clear
    echo -e "${BLUE}〢─────────────〢 ${WHITE}CONFIGURANDO FIREWALL ( UFW ) ${BLUE}〢────────────〢"
    local color_ ufw_installed ufw_status ufw_file ports_allow ports_deny
    ufw_installed=$(dpkg -l | grep -E "^ii" | grep -E "ufw" | wc -l)
    ufw_status=$(ufw status | grep -Eo "inactive" &>/dev/null && echo "[ INACTIVO ]" || echo "[ ACTIVO ]")
    ufw_file="/etc/default/ufw"
    
    show_info(){
        # ! UFW IS RUNNING OR INSTALLED
        if [[ "${ufw_installed}" -eq 1 ]];then
            [[ "${ufw_status}" =~ "[ INACTIVO ]" ]] && color_="${RED}" ||  color_="${GREEN}"
            local nn_length_=$(echo 60 - ${#ufw_status} - 4 | bc)
            printf "${WHITE}〢%3s : ${color_}%${#ufw_status}s ${WHITE}%${nn_length_}s\n" "UFW" "${ufw_status}" "〢"
        else
            printf "${WHITE}〢%3s : ${RED}%60s ${WHITE}%15s\n" "UFW" "[ NO INSTALADO ] NO SE PUEDE EJECUTAR EL SCRIPT DE FIREWALL." "〢"
            bar "apt-get install ufw -y"
            if [ $? -eq 0 ]; then
                info "SE HA INSTALADO EL SERVICIO UFW."
                # disabled ipv6
                sed -i "s/IPV6=yes/IPV6=no/" "${ufw_file}"
                sleep 2
                cfg_firewall_ufw
            else
                error "NO SE HA INSTALADO EL SERVICIO UFW." ; exit $?
            fi
        fi
        # ! Total de puertos permitidos/bloqueados
        ports_allow=$(ufw status | grep "ALLOW" -c )
        ports_deny=$(ufw status | grep "DENY" -c )
        logfile="/var/log/ufw.log"
        printf "${WHITE}〢%8s : ${GREEN}%${#logfile}s ${WHITE}%$((60 - 9 - ${#logfile}))s\n" "LOG-FILE" "${logfile}" "〢"
        printf "${WHITE}〢%18s : ${GREEN}%${#ports_allow}s ${WHITE}%$((60 - 19 - ${#ports_allow} ))s\n" "PUERTOS PERMITIDOS" "${ports_allow}" "〢"
        printf "${WHITE}〢%18s : ${RED}%${#ports_deny}s ${WHITE}%$(( 60 - 19 - ${#ports_deny} ))s\n" "PUERTOS BLOQUEADOS" "${ports_deny}" "〢"
        line_separator 60
        echo -e "${YELLOW}ESTE MENU PERMITE REALIZAR OPERACIONES HIPER-BASICAS."
        echo -e "${YELLOW}PARA UNA MEJOR ADMINISTRACIÓN, SE RECOMIENDA LEER LA DOCUMENTACION.${WHITE}"
        line_separator 60
    }
    show_info
    if [[ "${ufw_status}" =~ "[ INACTIVO ]" ]];then
        option_color 1 "ACTIVAR FIREWALL"

    else
        option_color 1 "DESACTIVAR FIREWALL"
    fi
    option_color 2 "PERMITIR PUERTOS"
    option_color 3 "BLOQUEAR PUERTOS"
    option_color 4 "LISTAR TODAS LAS REGLAS"
    option_color M "MENÚ PRINCIPAL"
    option_color E "SALIR"

    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " opt
        case $opt in
            1) # ACTIVAR/DESACTIVAR FIREWALL
                if [[  "${ufw_status}" =~ "[ INACTIVO ]" ]];then
                    info "Habilitar el firewall,podria ocasionar una reconexion de todas las conexiones."
                    bar "ufw --force enable"
                else
                    bar "ufw disable"
                fi
                sleep 3
                cfg_firewall_ufw
                ;;
            2) deny_allow_port_ufw_input "allow" ;;
            3) deny_allow_port_ufw_input "deny" ;;
            4) clear ; less <<< $(ufw status) ; cfg_firewall_ufw ;;
            "cls" | "CLS") clear && cfg_firewall_ufw ;;
            [Mm]) fenix ;;
            q|Q|e|E) exit 0 ;;
            *) tput cuu1 && tput el1
            esac
    done
}

cfg_timezone(){
    trap ctrl_c SIGINT SIGTERM
    clear
    echo -e "${BLUE}〢─────────────〢 ${WHITE}CONFIGURANDO LA ZONA HORARIA ${BLUE}〢──────────────〢"
    local timezone_actual=$(cat /etc/timezone)
    local length_=$(echo 62 - ${#timezone_actual} - 7 | bc)
    printf "${WHITE}〢%7s ${GREEN}%${#timezone_actual}s ${WHITE}%${length_}s\n" "ACTUAL:" "${timezone_actual}" "〢"
    line_separator 61
    # list country hispanoamerica                                         # !chile
    local opt_for_timedatectl=("Mexico_City" Bogota Madrid "Argentina/Buenos_Aires" Caracas Lima "Santiago" Guatemala Guayaquil Cuba "Paz" "Santo_Domingo" Tegucigalpa "El_Salvador" Asuncion Managua "Costa_Rica" "Puerto_Rico" Panama Montevideo) 
    local country_list=(Mexico Colombia España Argentina Venezuela Peru Chile Guatemala Ecuador Cuba Bolivia "Republica Dominicana" Honduras Salvador Paraguay Nicaragua "Costa Rica" "Puerto Rico" Panama Uruguay)
    for i in "${!country_list[@]}";do
        local length_=$(echo 62 - ${#country_list[i]} - ${#i} - 4 | bc)
        printf "${WHITE}〢[%${#i}s] : ${GREEN}%${#country_list[$i]}s ${WHITE}%${length_}s\n" "${i}" "${country_list[$i]}" '〢'
    done
    line_separator 61
    while true;do
        read -r -p "$(echo -e "${BLUE}[*] Zona Horaria [0-19]${WHITE}") : " opt
        if [[ "${opt}" =~ ^[0-9]+$ ]];then
            if [ "${opt}" -ge 0 ] && [ "${opt}" -lt ${#opt_for_timedatectl[@]} ];then
                local timezone_="${opt_for_timedatectl[$opt]}"
                break
            fi
        else
            error "Opcion no valida."
            continue
        fi
    done        
    local timezone=$(timedatectl list-timezones | grep  "${timezone_}"  )
    timedatectl set-timezone ${timezone} && {
        info "Zona horaria ${GREEN}${timezone}${WHITE} seleccionada."
        sleep 3
        fenix
    } || {
        error "No se ha podido seleccionar la zona horaria ${timezone}."
        sleep 3
        fenix
    }
}

cfg_fail2ban(){
    trap ctrl_c SIGINT SIGTERM
    clear
    echo -e "${BLUE}〢──────────────〢 ${WHITE}CONFIGURACIÓN DE FAIL2BAN${BLUE} 〢───────────────〢"
    local fail2ban_status=$(systemctl is-active fail2ban &>/dev/null;echo $?)
    local fail2ban_log_file="/var/log/fail2ban.log"
    show_info(){
        
        if [[ "${fail2ban_status}" -eq 0 ]];then
            printf "${WHITE}〢%8s : ${GREEN}%10s ${WHITE}%41s\n" "FAIL2BAN" "[ ACTIVO ]" "〢"
        else
            printf "${WHITE}〢%8s : ${RED}%10s ${WHITE}%41s\n" "FAIL2BAN" "[ INACTIVO ]" "〢"
        fi
        printf "${WHITE}〢%8s : ${GREEN}%${#fail2ban_log_files}s ${WHITE}%$((60 - 9 - ${#fail2ban_log_file}))s\n" "LOG-FILE" "${fail2ban_log_file}" "〢"
        line_separator 60

    }
    show_info
    echo -e "${YELLOW}FAIL2BAN PREVIENE QUE SU SERVIDOR SEA VICTIMA DE ATAQUE DE FUERZA BRUTA${WHITE}"
    echo -e  "${YELLOW}LO RECOMENDABLE ES ${RED}NO${YELLOW} DESACTIVARLO."
    
    line_separator 60
    [[ "${fail2ban_status}" -eq 0 ]] && option_color 1 "DESACTIVAR FAIL2BAN" || option_color 1 "ACTIVAR FAIL2BAN"
    option_color 2 "VER ARCHIVO DE REGISTRO"
    option_color 3 "REINICIAR FAIL2BAN"
    option_color M "MENÚ PRINCIPAL"
    option_color E "SALIR"
    
    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "\33[2K\r${WHITE}[$BBLUE${prompt}${WHITE}")] : " opt
        case $opt in
            1) [[ "${fail2ban_status}" -eq 0 ]] && bar "systemctl stop fail2ban" || bar "systemctl start fail2ban"
                sleep 3
                cfg_fail2ban
                ;;
            2) clear ; [[ "${simple_ui}" == "true" ]] && nano "${fail2ban_log_file}" || less "${fail2ban_log_file}" clear ; cfg_fail2ban ;;
            3) # REINICIAR FAIL2BAN
                bar "systemctl restart fail2ban"
                sleep 4
                cfg_fail2ban
                ;;
            "cls" | "CLS") clear && cfg_fail2ban ;;
            [Mm]) fenix ;;
            q|Q|e|E) exit 0 ;;
            *) tput cuu1 && tput el1 ;;
            esac
    done
    
}

speedtest_(){
    package_installed speedtest-cli || bar "apt install speedtest-cli -y"
    local result_=$(speedtest --simple)
    local result_=($(echo "${result_}" | sed -r 's/^.*([0-9]{1,3}[\.]{1}[0-9]{1,3}[\.]{1}[0-9]{1,3}[\.]{1}[0-9]{1,3}).*$/\1/'))
    
    local ping="${result_[1]} ${result_[2]}"
    local download_speed="${result_[4]} ${result_[5]}"
    local upload_speed="${result_[7]} ${result_[8]}"

    local lenght_ping=$(echo 60 - 5 -${#ping} | bc) 
    local lenght_down=$(echo 60 - 22 -${#download_speed} | bc) 
    local lenght_up=$(echo 60 - 20 -${#upload_speed} | bc) 
    
    printf "${WHITE}〢%4s : ${GREEN}%${#ping}s ${WHITE}%${lenght_ping}s\n" "PING" "${ping}" "〢"
    printf "${WHITE}〢%21s : ${GREEN}%${#download_speed}s ${WHITE}%${lenght_down}s\n" "VELOCIDAD DE DESCARGA" "${download_speed}" "〢"
    printf "${WHITE}〢%19s : ${GREEN}%${#upload_speed}s ${WHITE}%${lenght_up}s\n" "VELOCIDAD DE SUBIDA" "${upload_speed}" "〢"
}

cfg_blockads(){
    # 0 = activar , 1 = desactivar
    local opt="$1"
    local host_url="https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt" # ADAWAY
    local file_to_create="/etc/block-ads-fenixmanager-actived"
    if [[ "${opt}" -eq 0 ]];then
        info "Actualizando lista de hosts bloqueados..."
        info "Descargando lista de hosts bloqueados desde ${GREEN}${host_url}${WHITE}..."
        local remote_content=$(curl -s "${host_url}")
        local local_host_file_content=$(cat /etc/hosts)
        cp /etc/hosts /etc/hosts.bak
        echo "${remote_content}" >> /etc/hosts
        if [[ "${local_host_file_content}" != "${remote_content}" ]];then
            info "Bloqueador de anuncios instalado correctamente."
            info "Al usar su vps, no se mostrarán los anuncios de publicidad. ( ${GREEN}Youtube, Facebook, Twitter, ${WHITE}etc )"
            touch ${file_to_create}
        else
            error "No se ha podido actualizar la lista de hosts bloqueados."
        fi
    else
        rm -f "${file_to_create}"
        mv /etc/hosts.bak /etc/hosts
        if [[ -f "${file_to_create}" ]];then
            error "No se ha podido desactivar el bloqueador de anuncios."
        else
            info "Bloqueador de anuncios desactivado correctamente."
        fi
    fi
}

cfg_fenix_settings(){
    trap ctrl_c SIGINT SIGTERM
    clear
    echo -e "${BLUE}〢───────────────〢 ${WHITE}AJUSTES DE FENIX-MANAGER${BLUE} 〢─────────────〢"
    
    local preferences="/etc/FenixManager/preferences.bash"

    [[ ! -f "${preferences}" ]] && touch "${preferences}"
    [[ "${simple_ui}" == 'false' ]] && {
        printf "${WHITE}〢%-18s ${WHITE}%$(echo 72 - 18 | bc )s\n" " MENU DE INCIO: " "〢"
    } || {
        printf "${WHITE}〢%-18s ${WHITE}%$(echo 60 - 18 | bc )s\n" " MENU DE INCIO: " "〢"
    }
    
    # [[ "${show_fenix_banner}" == 'false' ]] && {
        # option_color 0 "${GREEN}MOSTAR${WHITE} BANNER DE FENIX-MANAGER ( OCULTAR TEXTO )"
    # } || {
        # option_color 0 "${GREEN}MOSTAR${WHITE} TEXTO DE FENIX-MANAGER ( OCULTAR BANNER )"   
    # }

    local home_var_val=("show_fenix_banner" "hide_first_panel" "hide_second_panel" "hide_third_panel" "hide_ports_open_services_in_home_menu")
    local home_var_desc=("banner de Fenix-Manager" "panel de informacion (os,etc)" "panel de usuarios ssh" "panel de adaptadores de red" "panel de puertos abiertos")
    for ((i=0;i<${#home_var_val[@]};i++));do
        local var_name="${home_var_val[$i]}"
        local var_value="$(grep -o "${var_name}=.*" "/etc/FenixManager/preferences.bash" | cut -d "=" -f 2 | tr "'" " " | xargs)" # get value of var_name
        local var_desc="${home_var_desc[$i]}"
        [[ "${var_value}" =~ "false" ]] && option_color "$i" "${RED}OCULTAR${WHITE} ${var_desc^^}" || option_color $i "${GREEN}MOSTRAR${WHITE} ${var_desc^^}"
    done

    [[ "${simple_ui}" == 'false' ]] && {
        printf "${WHITE}〢%-21s ${WHITE}%$(echo 72 - 21 | bc )s\n" " MENU DE PROTOCOLOS: " "〢"
    } || {
        printf "${WHITE}〢%-21s ${WHITE}%$(echo 60 - 21 | bc )s\n" " MENU DE PROTOCOLOS: " "〢"
    }
    [[ "${hide_ports_open_services_in_protocol_menu}" == "false" ]] && option_color 5 "${RED}OCULTAR${WHITE} PUERTOS ABIERTOS ( DROPBEAR,SSH,ETC )" || option_color 5 "${GREEN}MOSTRAR${WHITE} PUERTOS ABIERTOS ( DROPBEAR,SSH,ETC )"
    [[ "${simple_ui}" == 'false' ]] && line_separator 68 || line_separator 58
    option_color M "VOLVER AL MENU PRINCIPAL"
    option_color E "SALIR"
    
    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " opt
        case ${opt} in
            0)
                [[ "${show_fenix_banner}" == "false" ]] && {
                    sed -i "s/show_fenix_banner=.*/show_fenix_banner='true'/g" "${preferences}"
                } || {
                    sed -i "s/show_fenix_banner=.*/show_fenix_banner='false'/g" "${preferences}"
                }
                sleep 1.5
                fenix
                ;;
            1) # ! 
                [[ "${hide_first_panel}" == "false" ]] && {
                    sed -i "s/hide_first_panel=.*/hide_first_panel='true'/g" "${preferences}"
                } || {
                    sed -i "s/hide_first_panel=.*/hide_first_panel='false'/g" "${preferences}"
                }
                sleep 1.5
                fenix
                ;;
            2)
                [[ "${hide_second_panel}" == "false" ]] && {
                    sed -i "s/hide_second_panel=.*/hide_second_panel='true'/g" "${preferences}"
                } || {
                    sed -i "s/hide_second_panel=.*/hide_second_panel='false'/g" "${preferences}"
                }
                sleep 1.5
                fenix
                ;;
            3)
                [[ "${hide_third_panel}" == "false" ]] && {
                    sed -i "s/hide_third_panel=.*/hide_third_panel='true'/g" "${preferences}"
                } || {
                    sed -i "s/hide_third_panel=.*/hide_third_panel='false'/g" "${preferences}"
                }
                sleep 1.5
                fenix
                ;;
            4)
                [[ "${hide_ports_open_services_in_home_menu}" == "false" ]] && {
                    sed -i "s/hide_ports_open_services_in_home_menu=.*/hide_ports_open_services_in_home_menu='true'/g" "${preferences}"
                } || {
                    sed -i "s/hide_ports_open_services_in_home_menu=.*/hide_ports_open_services_in_home_menu='false'/g" "${preferences}"
                }
                sleep 1.5
                fenix
                ;;
            5)
                [[ "${hide_ports_open_services_in_protocol_menu}" == "false" ]] && {
                    sed -i "s/hide_ports_open_services_in_protocol_menu=.*/hide_ports_open_services_in_protocol_menu='true'/g" "${preferences}"
                } || {
                    sed -i "s/hide_ports_open_services_in_protocol_menu=.*/hide_ports_open_services_in_protocol_menu='false'/g" "${preferences}"
                }
                sleep 1.5
                fenix
                ;;
            
            [Mm])
                fenix
                ;;
            q|Q|e|E)
                exit 0
                ;;
            esac
    done
}   

limit_bandwidth(){
    trap ctrl_c SIGINT SIGTERM
    local user=$(logname)
    local preferences="/etc/FenixManager/preferences.bash"
    local interfaces=$(ls /sys/class/net | grep -v lo)
    [[ "${limit_bandwidth}" == "true" ]] && {
        for interface in ${interfaces};do
            wondershaper clean ${interface} &>/dev/null || {
                error "Error al eliminar el limite de velocidad de la interfaz ${interface}"
                exit $?
            }
        done
        sed -i "s/limit_bandwidth=.*/limit_bandwidth='false'/g" "${preferences}"
        info "LIMITE DE ANCHO DE BANDA DESACTIVADO"
    } || {
        package_installed "wondershaper" || {
            bar "apt-get install wondershaper -y"
        }
        info "Estas apunto de limitar ${RED}TODO${WHITE} el trafico de tu servidor vps."
        info "Esto incluye tu usuario actual ( ${user} ). ( Es recomendable habilitar,cuando este servidor sea solo exclusivo para usuarios publicos )."
        until [[ "${download}" =~ ^[0-9]+$ ]];do
            trap ctrl_c SIGINT SIGTERM
            read -p "$(echo -e "${WHITE}[*] Ingrese el limite de descarga en Kbps ( Kilo Bytes Per Second ) : ")" download
        done
        while [[ "${upload}" =~ ^[0-9]+$ ]];do
            trap ctrl_c SIGINT SIGTERM
            read -p "$(echo -e "${WHITE}[*] Ingrese el limite de subida en Kbps ( Kilo Bytes Per Second ) : ")" upload
        done
        for interface in ${interfaces};do
            wondershaper ${interface} ${download} ${upload} || {
                error "Error al limitar el trafico de ${interface}"
                exit $?
            }
        done
        echo "limit_bandwidth='true'" >> "${preferences}"
        info "Descarga: ${download} Kbps"
        info "Subida: ${upload} Kbps"
        info "LIMITE DE ANCHO DE BANDA ACTIVADO"
    }
}


block_p2p_and_torrent(){
    package_installed "xtables-addons-common" || {
        bar "apt-get install xtables-addons-common -y"
    }
    [[ "${deny_p2p_torrent}" == 'true' ]]  && {
        iptables -D FORWARD -p tcp -m ipp2p --bit -j DROP
        iptables -D FORWARD -p udp -m ipp2p --bit -j DROP
        info "P2P y Torrents desbloqueados."
        sed -i "s/deny_p2p_torrent=.*/deny_p2p_torrent='false'/g" "/etc/FenixManager/preferences.bash"
    } || {
        iptables -I FORWARD -p tcp -m ipp2p --bit -j DROP
        iptables -I FORWARD -p udp -m ipp2p --bit -j DROP
        info "P2P y Torrents bloqueados."
        [[ -z "${deny_p2p_torrent}" ]] && echo "deny_p2p_torrent='true'" >> "/etc/FenixManager/preferences.bash" ||sed -i "s/deny_p2p_torrent=.*/deny_p2p_torrent='true'/g" "/etc/FenixManager/preferences.bash"
    }
}