#!/usr/bin/bash

source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/color.bash"
source "/etc/FenixManager/funciones/hitman.bash"
source "/etc/FenixManager/preferences.bash"

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
    separator "CONFIGURACIÓN DE HITMAN"
    show_info(){
        # 69
        # 67
        local cron_is_running=$(ps -ef | grep -v grep | grep cron | wc -l)
        # ! CHECK IF CRON IS RUNNING
        if [ $cron_is_running -eq 0 ]; then
            printf "${WHITE}〢%4s : ${RED}%54s ${WHITE}%10s\n" "CRON" "[ DETENIDO ] NO SE PUEDE EJECUTAR EL SCRIPT DE HITMAN." "〢"
            bar "systemctl start cron"
            if [ $? -eq 0 ]; then info "SE HA INICIADO EL SERVICIO CRON." ; sleep 4 && cfg_hitman ; else error "NO SE HA INICIADO EL SERVICIO CRON. CONTACTESE CON EL ADMINISTRADOR." ; exit $? ; fi
        else
            printf "${WHITE}〢%4s : ${GREEN}%16s ${WHITE}%48s\n" "CRON" "[ EJECUTANDOSE ]" "〢"
        fi
        # ! CHECK IF CRON-FILE EXISTS
        if [ ! -f "$fenixmanager_crontab_file" ]; then
            error "NO SE HA ENCONTRADO EL ARCHIVO CRONTAB DE FENIXMANAGER."
            sleep 3
            add_cront_job_for_hitman
        else
            printf "${WHITE}〢%9s : ${GREEN}%${#fenixmanager_crontab_file}s ${WHITE}%35s\n" "CRON-FILE" "${fenixmanager_crontab_file}" "〢"
        fi
        printf "${WHITE}〢%15s : ${GREEN}%${#hitman_logfile}s ${WHITE}%21s\n" "HITMAN-LOG-FILE" "${hitman_logfile}" "〢"
        line_separator 67
        local info_hour_del_expired_acc="DIARIAMENTE, A LAS 00:00: HITMAN ELIMINARA LAS CUENTAS EXPIRADAS."
        printf "${WHITE}〢${YELLOW}%${#info_hour_del_expired_acc}s ${WHITE}%3s\n" "${info_hour_del_expired_acc}" "〢"
        local info_check_acc_exceded_limit="CADA ${minutes_} MINUTOS,HITMAN COMPROBARA SI HAY CUENTAS CON EXCEDENTE DE LIMITE DE CONEXIONES."
        printf "${WHITE}〢${YELLOW}%${#info_check_acc_exceded_limit}s ${WHITE}%3s\n" "${info_check_acc_exceded_limit}" "〢"
        line_separator 67
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
                [[ -f "${hitman_logfile}" ]] && cat "${hitman_logfile}" || info "No hay registro de hitman."
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
    separator "CONFIGURACION  DE ( UFW ) " # ! 72
    local color_ ufw_installed ufw_status ufw_file ports_allow ports_deny
    ufw_installed=$(dpkg -l | grep -E "^ii" | grep -E "ufw" | wc -l)
    ufw_status=$(ufw status | grep -Eo "inactive" &>/dev/null && echo "[ INACTIVO ]" || echo "[ ACTIVO ]")
    ufw_file="/etc/default/ufw"
    show_info(){
        # ! UFW IS RUNNING OR INSTALLED
        if [[ "${ufw_installed}" -eq 1 ]];then
            [[ "${ufw_status}" =~ "[ INACTIVO ]" ]] && color_="${RED}" ||  color_="${GREEN}"
            local nn_length_=$(echo 71 - ${#ufw_status} - 3 | bc)
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
        printf "${WHITE}〢%8s : ${GREEN}%${#logfile}s ${WHITE}%47s\n" "LOG-FILE" "${logfile}" "〢"
        printf "${WHITE}〢%18s : ${GREEN}%${#ports_allow}s ${WHITE}%$(echo 71 - 18 - ${#ports_allow} | bc )s\n" "PUERTOS PERMITIDOS" "${ports_allow}" "〢"
        printf "${WHITE}〢%18s : ${RED}%${#ports_deny}s ${WHITE}%$(echo 71 - 18 - ${#ports_deny} | bc )s\n" "PUERTOS BLOQUEADOS" "${ports_deny}" "〢"
        line_separator 72
        printf "${WHITE}〢${YELLOW}%71s ${WHITE}%0s\n" "ESTE MENU PERMITE REALIZAR OPERACIONES HIPER-BASICAS SOBRE EL FIREWALL." "〢"
        printf "${WHITE}〢${YELLOW}%68s ${WHITE}%7s\n" "PARA UNA MEJOR ADMINISTRACIÓN, SE RECOMIENDA LEER LA DOCUMENTACION." "〢"
        line_separator 72
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
            2) # PERMITIR PUERTOS
                deny_allow_port_ufw_input "allow"
                ;;
            3) # BLOQUEAR PUERTOS
                deny_allow_port_ufw_input "deny"
                ;;
            4) # LISTAR TODAS LAS REGLAS
                ufw status
                ;;
            "cls" | "CLS")
                clear
                cfg_firewall_ufw
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

cfg_timezone(){
    trap ctrl_c SIGINT SIGTERM
    clear
    separator "CONFIGURANDO LA ZONA HORARIA" # ! 74
    local timezone_actual=$(cat /etc/timezone)
    local length_=$(echo 75 - ${#timezone_actual} - 7 | bc)
    printf "${WHITE}〢%7s ${GREEN}%${#timezone_actual}s ${WHITE}%${length_}s\n" "ACTUAL:" "${timezone_actual}" "〢"
    line_separator 74
    # list country hispanoamerica                                         # !chile
    local opt_for_timedatectl=("Mexico_City" Bogota Madrid "Argentina/Buenos_Aires" Caracas Lima "Santiago" Guatemala Guayaquil Cuba "Paz" "Santo_Domingo" Tegucigalpa "El_Salvador" Asuncion Managua "Costa_Rica" "Puerto_Rico" Panama Montevideo) 
    local country_list=(Mexico Colombia España Argentina Venezuela Peru Chile Guatemala Ecuador Cuba Bolivia "Republica Dominicana" Honduras Salvador Paraguay Nicaragua "Costa Rica" "Puerto Rico" Panama Uruguay)
    for i in "${!country_list[@]}";do
        local length_=$(echo 75 - ${#country_list[i]} - ${#i} - 4 | bc)
        printf "${WHITE}〢[%${#i}s] : ${GREEN}%${#country_list[$i]}s ${WHITE}%${length_}s\n" "${i}" "${country_list[$i]}" '〢'
    done
    while true;do
        read -r -p "$(echo -e "${WHITE}[${BBLUE}Selecciona la opcion correspondiente a tu pais${WHITE}")] : " opt
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
    bar "timedatectl set-timezone ${timezone}"
    read -r -p "$(echo -e "${WHITE}[${BBLUE}Presiona ENTER para regresar al menu principal${WHITE}]")"
}

cfg_fail2ban(){
    trap ctrl_c SIGINT SIGTERM
    clear
    separator "CONFIGURACIÓN DE FAIL2BAN"
    local fail2ban_status=$(systemctl is-active fail2ban &>/dev/null;echo $?)
    local fail2ban_log_file="/var/log/fail2ban.log"
    show_info(){
        
        if [[ "${fail2ban_status}" -eq 0 ]];then
            printf "${WHITE}〢%8s : ${GREEN}%10s ${WHITE}%52s\n" "FAIL2BAN" "[ ACTIVO ]" "〢"
        else
            printf "${WHITE}〢%8s : ${RED}%10s ${WHITE}%50s\n" "FAIL2BAN" "[ INACTIVO ]" "〢"
        fi
        printf "${WHITE}〢%8s : ${GREEN}%${#fail2ban_log_files}s ${WHITE}%41s\n" "LOG-FILE" "${fail2ban_log_file}" "〢"
        line_separator 69
    }
    show_info
    echo -e "〢${YELLOW}FAIL2BAN PREVIENE QUE SU SERVIDOR SEA VICTIMA DE ATAQUE DE FUERZA BRUTA${WHITE}〢"
    printf "${WHITE}〢${YELLOW}%-35s ${WHITE}%38s\n" "LO RECOMENDABLE ES NO DESACTIVARLO." "〢"
    #echo -e "〢${YELLOW}${WHITE}〢"
    line_separator 69
    [[ "${fail2ban_status}" -eq 0 ]] && option_color 1 "DESACTIVAR FAIL2BAN" || option_color 1 "ACTIVAR FAIL2BAN"
    option_color 2 "VER ARCHIVO DE REGISTRO"
    option_color 3 "REINICIAR FAIL2BAN"
    option_color M "MENÚ PRINCIPAL"
    option_color E "SALIR"
    
    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " opt
        case $opt in
            1) # ACTIVAR/DESACTIVAR FAIL2BAN
                if [[ "${fail2ban_status}" -eq 0 ]];then
                    bar "systemctl stop fail2ban"
                else
                    bar "systemctl start fail2ban"
                fi
                sleep 3
                cfg_fail2ban
                ;;
            2) # VER ARCHIVO DE REGISTRO
                less "${fail2ban_log_file}"
                ;;
            3) # REINICIAR FAIL2BAN
                bar "systemctl restart fail2ban"
                sleep 4
                cfg_fail2ban
                ;;
            "cls" | "CLS")
                clear
                cfg_fail2ban
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

speedtest_(){
    package_installed speedtest-cli || bar "apt install speedtest-cli -y"
    info "Por favor, espera unos segundos mientras se realiza la prueba de velocidad..."
    local result_=$(speedtest --simple)
    local result_=($(echo "${result_}" | sed -r 's/^.*([0-9]{1,3}[\.]{1}[0-9]{1,3}[\.]{1}[0-9]{1,3}[\.]{1}[0-9]{1,3}).*$/\1/'))
    
    local ping="${result_[1]} ${result_[2]}"
    local download_speed="${result_[4]} ${result_[5]}"
    local upload_speed="${result_[7]} ${result_[8]}"

    local lenght_ping=$(echo 81 - 4 -${#ping} | bc) 
    local lenght_down=$(echo 81 - 21 -${#download_speed} | bc) 
    local lenght_up=$(echo 81 - 19 -${#upload_speed} | bc) 
    
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
    separator "AJUSTES DE FENIX-MANAGER"
    local preferences="/etc/FenixManager/preferences.bash"

    [[ ! -f "${preferences}" ]] && touch "${preferences}"
    printf "${WHITE}〢%-18s ${WHITE}%$(echo 72 - 18 | bc )s\n" " MENU DE INCIO: " "〢"
    # [[ "${show_fenix_banner}" == "false" ]] && option_color 0 "MENU DE INCIO: ${RED}OCULTAR${WHITE} TEXTO SOBRE FENIXMANAGER ( MOSTRAR UN BANNER DE FENIX )" || option_color 0 "MENU DE INCIO: ${GREEN}MOSTRAR${WHITE} TEXTOS SOBRE FENIXMANAGER ( OCULTAR BANNER DE FENIX )"   
    # [[ "${hide_first_panel}" == "false" ]] && option_color 1 "MENU DE INCIO: ${RED}OCULTAR${WHITE} PRIMER PANEL ( RAM, CPU, OS, ETC )" || option_color 1 "MENU DE INCIO: ${GREEN}MOSTRAR${WHITE} PRIMER PANEL ( RAM, CPU, OS, ETC )"
    # [[ "${hide_second_panel}" == "false" ]] && option_color 2 "MENU DE INCIO: ${RED}OCULTAR${WHITE} SEGUNDO PANEL ( CONTADOR DE USUARIOS SSH )" || option_color 2 "MENU DE INCIO: ${GREEN}MOSTRAR${WHITE} SEGUNDO PANEL ( CONTADOR DE USUARIOS SSH )"
    # [[ "${hide_third_panel}" == "false" ]] && option_color 3 "MENU DE INICIO: ${RED}OCULTAR${WHITE} TERCER PANEL ( ESTADISTICAS DEL ADAPTADOR DE RED )" || option_color 3 "MENU DE INICIO: ${GREEN}MOSTRAR${WHITE} TERCER PANEL ( ESTADISTICAS DEL ADAPTADOR DE RED )"
    # [[ "${hide_ports_open_services_in_home_menu}" == "false" ]] && option_color 4 "MENU DE INICIO: ${RED}OCULTAR${WHITE} PUERTOS ABIERTOS ( DROPBEAR,SSH,ETC )" || option_color 4 "MENU DE INICIO: ${GREEN}MOSTRAR${WHITE} PUERTOS ABIERTOS ( DROPBEAR,SSH,ETC )"
    # [[ "${hide_ports_open_services_in_protocol_menu}" == "false" ]] && option_color 5 "MENU DE PROTOCOLOS: ${RED}OCULTAR${WHITE} PUERTOS ABIERTOS ( DROPBEAR,SSH,ETC )" || option_color 5 "MENU DE PROTOCOLOS: ${GREEN}MOSTRAR${WHITE} PUERTOS ABIERTOS ( DROPBEAR,SSH,ETC )"
    [[ "${show_fenix_banner}" == "false" ]] && option_color 0 "${RED}OCULTAR${WHITE} TEXTO SOBRE FENIXMANAGER ( MOSTRAR UN BANNER DE FENIX )" || option_color 0 "${GREEN}MOSTRAR${WHITE} TEXTOS SOBRE FENIXMANAGER ( OCULTAR BANNER DE FENIX )"   
    [[ "${hide_first_panel}" == "false" ]] && option_color 1 "${RED}OCULTAR${WHITE} PRIMER PANEL ( RAM, CPU, OS, ETC )" || option_color 1 "${GREEN}MOSTRAR${WHITE} PRIMER PANEL ( RAM, CPU, OS, ETC )"
    [[ "${hide_second_panel}" == "false" ]] && option_color 2 "${RED}OCULTAR${WHITE} SEGUNDO PANEL ( CONTADOR DE USUARIOS SSH )" || option_color 2 "${GREEN}MOSTRAR${WHITE} SEGUNDO PANEL ( CONTADOR DE USUARIOS SSH )"
    [[ "${hide_third_panel}" == "false" ]] && option_color 3 "${RED}OCULTAR${WHITE} TERCER PANEL ( ESTADISTICAS DEL ADAPTADOR DE RED )" || option_color 3 "${GREEN}MOSTRAR${WHITE} TERCER PANEL ( ESTADISTICAS DEL ADAPTADOR DE RED )"
    [[ "${hide_ports_open_services_in_home_menu}" == "false" ]] && option_color 4 "${RED}OCULTAR${WHITE} PUERTOS ABIERTOS ( DROPBEAR,SSH,ETC )" || option_color 4 "${GREEN}MOSTRAR${WHITE} PUERTOS ABIERTOS ( DROPBEAR,SSH,ETC )"
    [[ $columns -le 78 ]] && line_separator 70 || line_separator 68
    printf "${WHITE}〢%-21s ${WHITE}%$(echo 72 - 21 | bc )s\n" " MENU DE PROTOCOLOS: " "〢"
    [[ "${hide_ports_open_services_in_protocol_menu}" == "false" ]] && option_color 5 "${RED}OCULTAR${WHITE} PUERTOS ABIERTOS ( DROPBEAR,SSH,ETC )" || option_color 5 "${GREEN}MOSTRAR${WHITE} PUERTOS ABIERTOS ( DROPBEAR,SSH,ETC )"
    [[ $columns -le 78 ]] && line_separator 70 || line_separator 68
    option_color 6 "CONFIGURAR UN DOMINIO: ESTO ES IRRELEVANTE, SOLO SE USARA/MOSTRARA EN CASOS NECESARIOS"
    option_color M "VOLVER AL MENU PRINCIPAL"
    option_color E "SALIR"
    
    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " opt
        case ${opt} in
            0)
                [[ "${show_fenix_banner=}" == "false" ]] && {
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
            6) # Add domain
                # read domain name
                read -p "$(echo -e "${WHITE}[*] Ingrese el nombre del dominio : ")" domain
                echo "domain_='$domain'" >> "${preferences}"
                info "Dominio ${domain} agregado"
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