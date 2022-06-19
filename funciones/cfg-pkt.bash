#!/bin/bash

source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/color.bash" 2>/dev/null
source "/etc/FenixManager/funciones/ovpn.bash"

script_executed_with_root_privileges


cfg_squid_proxy(){
    clear
    trap ctrl_c SIGINT SIGTERM
    squid_file_config='/etc/squid/squid.conf'
    echo -e  "${BLUE}〢─────────────〢${WHITE} CONFIGURANDO SQUID-PROXY ${BLUE}〢─────────────────〢${WHITE}"
    show_info(){
        # 70
        if [[ ! -f $squid_file_config ]];then
            error "El archivo de configuracion de squid no existe."
            exit 1
        fi
        local _color_ips _color_dominios squid_is_running _squid_run_color one_length two_length three_length four_length
        local ports_squid=$(cat $squid_file_config | grep http_port | awk '{print $2}' | tr "\n" " ")
        
        if [[ -f "/etc/squid/ip_allows" ]];then
            local number_host_ip_in_white_list=$(wc -l < /etc/squid/ip_allows)
            _color_ips=${GREEN}
        else
            local number_host_ip_in_white_list='0'
            _color_ips=${RED}
        fi
        if [[ -f "/etc/squid/domain_allow" ]];then
            local number_host_domain_in_white_list=$(wc -l < /etc/squid/domain_allow)
            _color_dominios=${GREEN}

        else
            local number_host_domain_in_white_list='0'
            _color_dominios=${RED}
        fi
        if systemctl is-active 'squid' &>/dev/null;then
            squid_is_running="[ EN EJECUCION ]"
            _color_squid_run=${GREEN}
        else
            squid_is_running="[ DETENIDO ]"
            _color_squid_run=${RED}
        fi
        if [[ -f /etc/squid/users_passwd ]] && [[ ! -z $(cat /etc/squid/users_passwd) ]] && (grep "#SQUID AUTH CFG#" /etc/squid/squid.conf &>/dev/null);then 
            local auth_is_enable="[ ACTIVADO ]"
            _color_auth_enable=${GREEN}
        else
            local auth_is_enable="[ DESACTIVADO ]"
            _color_auth_enable=${RED}
        fi
        one_length=$(echo 8 + $(echo "${ports_squid}" | wc -c ) - 60 | bc | tr "-" " ")
        two_length=$(echo 24 + $(echo ${number_host_ip_in_white_list} | wc -c ) - 60 | bc | tr "-" " ")
        three_length=$(echo 28 + $(echo ${number_host_domain_in_white_list} | wc -c ) - 60 | bc | tr "-" " ")
        four_length=$(echo 6 + $(echo ${squid_is_running} | wc -c ) - 60 | bc | tr "-" " ")
        five_length=$(echo 14 + $(echo ${auth_is_enable} | wc -c ) - 60 | bc | tr "-" " ")

        printf "${WHITE}〢 %-7s : ${GREEN}%1s ${WHITE}%${one_length}s\n" "Puertos" "${ports_squid}" '〢'
        printf "${WHITE}〢 %-23s : ${_color_ips}%1s ${WHITE}%${two_length}s\n" "IP'S en la lista blanca" "${number_host_ip_in_white_list}" '〢'
        printf "${WHITE}〢 %-27s : ${_color_dominios}%1s ${WHITE}%${three_length}s\n" "Dominios en la lista blanca" "${number_host_domain_in_white_list}" '〢'
        printf "${WHITE}〢 %-13s : ${_color_auth_enable}%1s ${WHITE}%${five_length}s\n" "Autenticacion" "${auth_is_enable}" '〢'
        printf "${WHITE}〢 %-5s : ${_color_squid_run}%1s ${WHITE}%${four_length}s\n" "SQUID" "${squid_is_running}" '〢'
        line_separator 60

    }
    show_info
    option_color "1" "AGREGAR PUERTOS"
    option_color "2" "ELIMINAR PUERTOS"
    if systemctl is-active 'squid' &>/dev/null;then
        option_color "3" "REINICIAR SQUID-PROXY"
    else
        option_color "3" "INICIAR SQUID"
    fi
    option_color "4" "DETENER SQUID-PROXY"
    option_color "5" "AGREGAR/ELIMINAR AUTENTICACION"
    option_color "6" "AGREGAR/ELIMINAR HOST/IP DE LA LISTA BLANCA"
    option_color "7" "${RED}DESINSTALAR SQUID-PROXY"
    option_color "B" "MENU DE INSTALACION DE SOFTWARE"
    option_color "M" "MENU PRINCIPAL"
    option_color 'E' "SALIR"

    
    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(printf "\33[2K\r${WHITE}[$BBLUE${prompt}${WHITE}] : ")" option
        case $option in
            1) # Agregar puertos
                {
                    port_input
                    squid_port=${puertos_array[*]}
                    unset puertos_array

                    local http_port_line=$(grep "http_port" /etc/squid/squid.conf --line-number | head -n1 | cut -d: -f1 )
                    for i in ${squid_port[@]};do
                        ((http_port_line++))
                        sed -i "${http_port_line}i http_port $i" $squid_file_config
                    done
                    bar "systemctl restart squid"
                    if [[ ! $? -eq 0 ]];then
                        error "Error al agregar los puertos ${squid_port[*]} al archivo $squid_file_config"
                    fi
                }
                clear
                cfg_squid_proxy
                ;;
            2) # Eliminar puertos
                {
                    {   
                        trap ctrl_c SIGINT SIGTERM
                        ports=$(cat $squid_file_config | grep http_port | awk '{print $2}')
                        load_squid_ports=($ports)

                        count_=0
                        echo -e "${BLUE}[*] Selecciona los puertos a eliminar:"
                        for i in ${load_squid_ports[@]};do
                            echo -e "${WHITE}    [ ${GREEN}${count_}${WHITE} ] ${WHITE}$i"
                            ((count_++))
                        done
                        while true;do
                            read -p "$(echo -e "${GREEN}[*] Seleccione una opcion [1-${count_}] : ${WHITE}")" option_
                            if [[ $option_ =~ ^[0-9]+$ ]] && [[ $option_ -ge 0 ]] && [[ $option_ -lt ${#load_squid_ports[@]} ]];then break  ; else   continue ; fi
                        done
                        local ports_to_del=${load_squid_ports[$option_]}
                        
                        local line_del=$(grep --line-number "http_port ${ports_to_del}" ${squid_file_config} | cut -d: -f1  )
                        sed -i "${line_del}d" $squid_file_config
                        if bar "systemctl restart squid";then
                            info "Puerto ${load_squid_ports[option_]} eliminado correctamente"
                        else
                            info "Error el eliminar el puerto  ${load_squid_ports[option_]}."
                        fi
                    }
                }
                sleep 2
                clear
                cfg_squid_proxy
                ;;
            3) # reiniciar/iniciar squid
                if systemctl is-active 'squid' &>/dev/null;then
                  bar "systemctl restart squid"
                else
                    bar "systemctl start squid"
                fi
                sleep 2
                clear
                cfg_squid_proxy
                ;;
            4) # detener squid
                {
                if bar "systemctl stop squid";then
                    info "squid-proxy detenido"
                else
                    error "Error al detener squid-proxy"
                fi
                }
                sleep 2
                cfg_squid_proxy
                ;;
            5) # agreagar autenticacion
                {
                    trap ctrl_c SIGINT SIGTERM
                    if ! package_installed "apache2-utils";then bar "apt-get install apache2-utils -y" ; fi
                    squid_cfg="#SQUID AUTH CFG#\nauth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/users_passwd\nauth_param basic realm Squid proxy-caching web server\nauth_param basic credentialsttl 24 hours\nauth_param basic casesensitive off\nacl authenticated proxy_auth REQUIRED\nhttp_access allow authenticated\n#SQUID AUTH CFG END#"
                    if [[ -f /etc/squid/users_passwd ]] && [[ ! -z $(cat /etc/squid/users_passwd) ]] && (grep "#SQUID AUTH CFG#" /etc/squid/squid.conf &>/dev/null);then 
                        info "Ya se encuentra configurado un usuario para squid-proxy."
                        option_color "1" "ELIMINAR AUTENTICACION"
                        option_color "2" "CREAR UN NUEVO NOMBRE DE USUARIO/CONTRASEÑA"
                        read -p  "$(echo -e "${WHITE}[*] Seleccione una opcion [1-2]: ")" squid_option
                        case $squid_option in
                            1)
                                # find SQUID AUTH CFG in file
                                auth_cfg_line_number_init=$(grep '#SQUID AUTH CFG#' /etc/squid/squid.conf --line-number | cut -d: -f1)
                                auth_cfg_line_number_end=$(grep '#SQUID AUTH CFG END#' /etc/squid/squid.conf --line-number | cut -d: -f1)
                            if [[ -z $auth_cfg_line_number_init ]] || [[ -z $auth_cfg_line_number_end ]];then
                                error "No se encuentra la configuracion de autenticacion en el archivo squid.conf."
                                error "Elimine la configuracion manualmente y vuelva a intentarlo."
                                error 'Este error puede deberse a intervencion manual del usuario.'
                                exit 1
                            fi
                            sed -i "${auth_cfg_line_number_init},${auth_cfg_line_number_end}d" /etc/squid/squid.conf 
                            # find http_access deny all and move to the end line number
                            sed -i '/http_access deny all/d' /etc/squid/squid.conf 
                            echo 'http_access deny all' >> /etc/squid/squid.conf

                            if [[ $? -eq 0 ]];then
                                info "Autenticacion eliminada correctamente"
                                sleep 1.5
                                cfg_squid_proxy
                            else
                                error "Error al eliminar la autenticacion"
                            fi
                            ;;
                    esac
                fi
                
                echo -e "$squid_cfg" >> $squid_file_config
                # find http_access deny all and move to the end line number
                sed -i '/http_access deny all/d' /etc/squid/squid.conf 
                echo 'http_access deny all' >> /etc/squid/squid.conf
                bar "systemctl restart squid"
                while true;do
                    trap ctrl_c SIGINT SIGTERM
                    read -p "$(echo -e "${GREEN}[*] Nombre de usuario para squid: ${WHITE}")" username
                    if [[ -z $username ]];then continue ; fi
                    read -p "$(echo -e "${GREEN}[*] Contraseña para squid: ${WHITE}")" password
                    if [[ -z $password ]];then continue ; fi
                    break
                done
                htpasswd -b -c /etc/squid/users_passwd "$username" "$password" &>/dev/null
                if [[ $? -eq 0 ]];then
                    info "Autenticacion agregada correctamente."
                    info "Usuario: ${GREEN}$username${WHITE}"
                    info "Contraseña: ${GREEN}$username${WHITE}"
                    info "Guarde esta informacion en un lugar seguro."
                    info "En caso de perder la contraseña, debera regenerarla."
                    read -p "$(echo -e "${GREEN}[*] Presione enter para continuar...${WHITE}")"
                    cfg_squid_proxy
                else
                    error "Error al agregar la autenticacion"
                    sleep 5
                fi
                }
                ;;
            6) # agregar host/ip a la lista blanca.
                {
                # check if list is empty
                if [[ ! -z $(cat /etc/squid/domain_allow) ]];then
                    option_color "1" "ELIMINAR HOST/IP DE LA LISTA BLANCA"
                    option_color "2" "AGREGAR HOST/IP A LA LISTA BLANCA"
                    read -p "$(echo -e "[*] Seleccione una opcion [1-2]: ")" option
                    case $option in 
                        1)
                            echo -e "${RED}[*] ELIMINANDO HOST DE LA LISTA BLANCA...${WHITE}"
                            hosts=$(cat /etc/squid/domain_allow)
                            ips=$(cat /etc/squid/ip_allow)
                            ips_array=($ips)
                            hosts_array=($hosts)
                            hosts_and_ip=($hosts)
                            count_=1
                            for i in ${hosts[@]};do
                                echo -e "${WHITE}[ ${BLUE}${count_}${WHITE} ] ${GREEN}$i${WHITE}"
                                ((count_++))
                            done
                            get_all_ip_from_adapters
                            for ip in ${ips_array[@]};do
                                if [[ ! ${IPS_LISTS[@]} =~ $ip ]] && [[ ${ips_array[@]} =~ $ip ]];then
                                    echo -e "${WHITE}[ ${BLUE}${count_}${WHITE} ] ${GREEN}$ip${WHITE}"
                                    hosts_and_ip+=($ip)
                                    ((count_++))
                                fi
                            done

                            while true;do
                                read -p "$(echo -e "${BLUE}[*] Seleccione una opcion : ")" option_
                                if [[ ! $option_ -ge 1 ]] || [[ ! $option_ -le $count_ ]] || [[ -z $option_ ]];then continue ; fi
                                break
                            done
                            host_to_del=${hosts_and_ip[option_-1]}
                            if [[ $host_to_del =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];then in_file='/etc/squid/ip_allow' ; else in_file='/etc/squid/domain_allow' ;fi
                            sed -i "/${host_to_del}/d" $in_file
                            if [[ $? -eq 0 ]];then
                                info "HOST/IP ${RED}${host_to_del}${WHITE} eliminado correctamente."
                                sleep 1.5
                                cfg_squid_proxy
                            else
                                error "Error al eliminar el host."
                            fi
                            
                            ;;
                    esac

                fi

                trap ctrl_c SIGINT SIGTERM
                domain_regex="(?=^.{4,253}$)(^(?:[a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,}|xn--[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$)"
                while true;do
                    trap ctrl_c SIGINT SIGTERM
                    read -p "$(echo -e "${GREEN}[*] Host/IP a agregar: ${WHITE}")" host_ip
                    if [[ -z $host_ip ]];then continue ; fi
                    if [[ $host_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];then
                        ip_add=$host_ip
                        
                    else
                        if grep -P $domain_regex <<< "$host_ip" &>/dev/null;then
                            domain_add=$host_ip
                        else
                            error "El ($host_ip) no es una direccion ipv4 o hostname valido."
                            continue
                        fi
                    fi
                    break
                done
                if [[ ! -z $ip_add ]];then
                    echo "$ip_add" >> /etc/squid/ip_allow
                elif [[ ! -z $domain_add ]];then
                    echo "$domain_add" >> /etc/squid/domain_allow
                fi
                if [[ $? -eq 0 ]];then
                    h=${ip_add:-$domain_add}
                    info "${GREEN}$h${WHITE} agregado correctamente."
                    sleep 1.5
                    cfg_squid_proxy
                else
                    error "Error al agregar el host/ip"
                fi
                }
                ;;
            7) # desinstalar squid-proxy
                bar "sudo apt-get remove squid -y"
                if [[ $? -eq 0 ]];then
                    info "Squid-proxy desinstalado correctamente."
                    rm -rf /etc/squid
                    sleep 1.5
                    fenix
                else
                    error "Error al desinstalar squid-proxy."
                    sleep 1.5
                    exit 1
                fi
                ;;
            [bB]) # MENU DE INSTALACION
                option_menu_software
                ;;
            "cls" | "CLS")
                clear
                cfg_squid_proxy
                ;;
            e | E )
                # Salir
                exit 0
                ;;
            M | m )
                # Menu principal
                fenix
                ;;
            *) tput cuu1 && tput el1 ;;
        esac
    done
}

cfg_stunnel4() {
    unistall_stunnel4() {
        bar "service stunnel4 stop"
        killall stunnel4 &>/dev/null
        bar "apt-get remove stunnel4 -y"
        if [[ $? -eq 0 ]];then
            rm -rf /etc/stunnel4 
            rm -rf /etc/stunnel
            info "Stunnel4 desinstalado correctamente."
            sleep 1.5
        fi
    }
    change_ssl_cert(){
        stunnel4_whats_cert_to_use
        if [[  $CERT_FILE =~ ".pem" ]];then
            sed -i "s\cert =.*\cert = ${CERT_FILE}\g" /etc/stunnel/stunnel.conf
            # check if key exist in /etc/stunnel/stunnel.conf, if exist : delete
            grep -q "key =" /etc/stunnel/stunnel.conf && sed -i "/key =/d" /etc/stunnel/stunnel.conf
            
        else
            sed -i "s\cert =.*\cert = $CERT_FILE\g" /etc/stunnel/stunnel.conf
            # check if stunnel.conf load key file
            if grep "key" /etc/stunnel/stunnel.conf &>/dev/null;then
                sed -i "s\key =.*\key = $KEY_FILE\g" /etc/stunnel/stunnel.conf
            else
                local cert_line=$(grep -n "cert" /etc/stunnel/stunnel.conf | cut -d: -f1)
                sed -i "${cert_line}a key = $KEY_FILE" /etc/stunnel/stunnel.conf
            fi
        fi
        info "Certificado cambiado correctamente."
        bar "service stunnel4 restart"
        sleep 1.5
        cfg_stunnel4
    }
    show_info(){
        local file_conf="/etc/stunnel/stunnel.conf"
        if [[ ! -f $file_conf ]];then
            error "El archivo $file_conf no existe."
            info "Se recomienda,re-instalar stunnel4."
            info "Ejecute manualmente el comando: apt-get remove --purge stunnel4"
            info "Y luego, iniciar fenix nuevamente."
            exit 1
        fi
        local cert_conf=$(grep "cert" $file_conf | cut -d= -f2 | head -n1 | sed "s|${user_folder}|~|g")
        local key_conf=$(grep "key" $file_conf | cut -d= -f2 | sed "s|${user_folder}|~|g" )
        local total_custom_config accept_conn_ports
        accept_conn_ports=()
        
        total_custom_config=$(grep -E -o  "custom#[0-9]{0,9}" ${file_conf} 2>/dev/null| cut -d# -f 2 | tr "\n" " " | xargs)
        for i in ${total_custom_config};do
            local line_number=$(grep -o "custom#${i}" ${file_conf} --line-number | cut -d: -f1)
            #           accept port : connect port
            for i in {1..2};do
                ((line_number++))
                if [[ $i -eq 1 ]];then
                    local accept_conn_ports+="$(sed -n "${line_number}p" ${file_conf} | grep -E "[0-9]{1,}" -o):"
                else
                    local accept_conn_ports+="$(sed -n "${line_number}p" ${file_conf} | grep -E "[0-9]{1,}" -o) "
                fi
            done
        done
        
        if [[ $(service  stunnel4 status &>/dev/null;echo $?) -eq 0 ]];then
            local _color=( ${YELLOW} ${GREEN} )
        else
            local _color=( ${RED} ${RED} )
        fi
        printf "〢 ${_color[0]}%20s ${_color[1]}%20s ${WHITE}%20s\n" "ACCEPT" "CONNECT" '〢'
        
        IFS='|' read -r -a array <<< "$accept_conn_ports"
        for i in ${array[@]};do
            local accept=$(echo "${i}" | cut -d: -f1)
            local conn=$(echo "${i}" | cut -d: -f2)
            local accept_len=${#accept}
            local conn_len=${#conn}
            printf "〢 ${_color[0]}%18.5s ${_color[1]}%19.5s ${WHITE}%23s\n" "${accept}" "${conn}" '〢'
        done
        line_separator 60
        printf "〢 ${WHITE}%4s: ${GREEN}%-${#cert_conf}s ${WHITE}%$(echo 60 - 5 - ${#cert_conf}  | bc)s\n" "CERT" "${cert_conf}" '〢'
        if [[ -n $key_conf ]];then
            printf "〢 ${WHITE}%3s: ${GREEN}%-${#key_conf}s ${WHITE}%$(echo 60 - 4 - ${#key_conf}  | bc)s\n" "KEY" "${key_conf}" '〢'
        fi
        line_separator 60

    }
    trap ctrl_c SIGINT SIGTERM
    clear
    echo -e "${BLUE}〢──────────────〢${WHITE}CONFIGURANDO STUNNEL4 (SSL)${BLUE}〢───────────────〢${WHITE}"
    show_info
    
    
    stunnel_is_running=$(service  stunnel4 status &>/dev/null;echo $?)
    stunnel_file_config="/etc/stunnel/stunnel.conf"

    local cert_actuallly_installed=$(grep  "cert = " /etc/stunnel/stunnel.conf | tr -d "=" | cut -d" " -f3)
    cert_actuallly_installed=$(echo $cert_actuallly_installed | sed "s|${user_folder}|~|g")
                    
    
    option_color "1" "AGREGAR PUERTOS"
    option_color "2" "ELIMINAR PUERTOS"
    
    if [[ $stunnel_is_running -eq 0 ]];then
        option_color "3" "REINICIAR STUNNEL4"
        option_color "4" "DETENER STUNNEL4"
        option_color "5" "CAMBIAR CERTIFICADO SSL"
        option_color "6" "VER ESTADO DE STUNNEL4"
        option_color "7" "${RED}DESINSTALAR STUNNEL4"
    else
        option_color "3" "INICIAR STUNNEL4"
        option_color "4" "CAMBIAR CERTIFICADO SSL"
        option_color "5" "VER ESTADO DE STUNNEL4"
        option_color "6" "${RED}DESINSTALAR STUNNEL4"
    fi
    option_color "B" "MENU DE INSTALACION DE SOFTWARE"
    option_color "M" "MENU PRINCIPAL"
    option_color "E" "SALIR"

    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -p "$(echo -e "${WHITE}[${BBLUE}${prompt}${WHITE}")] : " option
        case $option in
            1) # agregar puertos
                {
                    port_input
                    local stunnel_new_port="${puertos_array[@]}" && unset puertos_array
                    for port in ${stunnel_new_port[@]};do
                        custom_config_installed=$(grep "custom#" -o -c ${stunnel_file_config} 2>/dev/null)
                        ((custom_config_installed++))
                        info "Agregando el puerto ${GREEN}$port${WHITE}."
                        redirect_to_service
                        local service_port=$SERVICE_REDIRECT

                        local base_cfg="\n[custom#${custom_config_installed}]\naccept = $port\nconnect = $service_port\n"
                        echo -e "$base_cfg" >> $stunnel_file_config
                    done
                    bar "service stunnel4 restart" && info "Puerto ${GREEN}${stunnel_new_port[@]}${WHITE} agregado correctamente" || error "Error al agregar el puerto ${GREEN}${stunnel_new_port[@]}${WHITE}."
                }
                cfg_stunnel4
                ;;
            2) # eliminar puertos
                local ports_in_cfg_file=$(grep "accept" /etc/stunnel/stunnel.conf | cut -d "=" -f 2 | cut -d ":" -f 2 | cut -d " " -f 2)
                if [[ -z $ports_in_cfg_file ]];then error "No hay puertos en el archivo de configuracion." ; sleep 1.5 ; cfg_stunnel4 ; fi
                {
                    local count=0
                    port_cfg_array=($ports_in_cfg_file)
                    echo -e "${WHITE}[*] Selecciona el puerto que deseas eliminar: "
                    for port in $ports_in_cfg_file;do
                        ((count++))
                        echo -e "${WHITE} [ ${BLUE}$count${WHITE} ] ${GREEN}$port"
                    done
                    
                    while true;do
                        trap ctrl_c SIGINT SIGTERM
                        read -p "$(echo -e "${BLUE}[*] Seleccione el puerto a eliminar : ${WHITE}")" ports_del
                        if [[ -z $ports_del ]]; then continue ; fi
                        if [[ $ports_del =~ ^[1-${count}]+$ ]];then
                            port=${port_cfg_array[$ports_del-1]}
                            local line_number=$(grep "^accept = $port" /etc/stunnel/stunnel.conf --line-number --only | cut -d ":" -f 1)
                            local del_custom_line=$(echo $line_number - 1 | bc)
                            local del_connect_line=$(echo $line_number + 1 | bc)
                            
                            local sed_str="${del_custom_line},${del_connect_line}d"
                            
                            sed -i $sed_str /etc/stunnel/stunnel.conf
                            sed -i '/^[[:space:]]*$/d' /etc/stunnel/stunnel.conf
                            service stunnel4 restart &>/dev/null
                            sleep 1.5
                            cfg_stunnel4
                            
                        fi
                    done
                }
                ;;
            3) # REINICIAR/INICIAR  stunnel4
                [[ $stunnel_is_running -eq 0 ]] && bar "service stunnel4 restart" || bar "service stunnel4 start"
                sleep 1.5    
                cfg_stunnel4
                
                ;;
            4) # DETENER/CAMBIAR CERTIFICADO SSL stunnel4
                [[ $stunnel_is_running -eq 0 ]] && bar "service stunnel4 stop" || change_ssl_cert
                sleep 1.5
                cfg_stunnel4
                ;;
            5) # CAMBIAR CERTIFICADO/VER ESTADO SSL
                [[ $stunnel_is_running -eq 0 ]] && {
                    change_ssl_cert
                    sleep 1.5
                    cfg_stunnel4
                } || systemctl status stunnel4
                ;;
            6) # VER ESTADO/DESINSTALAR STUNNEL4
                [[ $stunnel_is_running -eq 0 ]] && systemctl status stunnel4 || {
                    unistall_stunnel4
                    option_menu_software
                }
                ;;
            7) # DESINSTALAR STUNNEL4
                unistall_stunnel4
                option_menu_software
                ;;
            "cls" | "CLS")
                clear
                cfg_stunnel4
                ;;
            [bB])
                # Menu de instalacion de software
                option_menu_software
                ;;
            [mM])
                # Menu principal
                fenix
                ;;
            q|Q|e|E)
                # Salir
                exit 0
                ;;
            *)
                continue
                ;;
        esac
    done

    
}

cfg_shadowsocks(){
    trap ctrl_c SIGINT SIGTERM
    _config_uri() {
        obfs_server_pid=$(pidof obfs-server)
        local method=$(jq -r '.method' /etc/shadowsocks-libev/config.json)
        local passwd=$(jq -r '.password' /etc/shadowsocks-libev/config.json)
        local port=$(jq -r '.server_port' /etc/shadowsocks-libev/config.json)
        local public_ip=$(curl -s https://ipinfo.io/ip)
        local uri_encode=$(echo -n $method:$passwd@$public_ip:$port | base64 )
        uri_shadowsocks="ss://$uri_encode${extra_args}"
        echo -e "$uri_shadowsocks" > /etc/shadowsocks-libev/ss.txt
    }
    check_jq_is_installed(){
        if [[ ! -f /usr/bin/jq ]];then
            error "jq no esta instalado en el sistema."
            info "Instalando jq..."
            bar "apt-get install jq -y"
            if [[ $? -eq 0 ]];then
                info "jq instalado correctamente."
            else
                error "Error al instalar jq."
                exit 1
            fi
        fi
    }
    unistall_shadowsocks(){
        bar "service shadowsocks-libev stop"
        bar "apt-get remove shadowsocks-libev -y"
        if [[ $? -eq 0 ]];then
            local locate_files=$(locate shadowsocks-libev)
            for i in $locate_files;do rm -rf $i &>/dev/null ; done
            info "SHADOWSOCKS-LIBEV eliminado correctamente."
            read
        else
            error "Fallo al eliminar shadowsocks-libev."
        fi
        
    }
    clear
    echo -e "${BLUE}〢──────────────〢${WHITE} CONFIGURANDO SHADOWSOCKS ${BLUE}〢────────────────〢"
    check_jq_is_installed
    local shadowsocks_is_running=$(systemctl status shadowsocks-libev.service &>/dev/null;echo $?)
    
    ss_pid=$(pidof ss-server)
    obfs_server_pid=$(pidof obfs-server)
    
    local puerto_actual=$(jq -r '.server_port' /etc/shadowsocks-libev/config.json)
    local password_actual=$(jq -r '.password' /etc/shadowsocks-libev/config.json)
    local simple_obfs_installed=$(which obfs-server &>/dev/null)
    
    show_info() {
        ss_pid=$(pidof ss-server)
        obfs_server_pid=$(pidof obfs-server)
        local one_length two_length three_length
        one_length=$(echo 60 - $(echo "PUERTO ACTUAL ${puerto_actual}" | wc -c ) | bc )
        two_length=$(echo 61 - $(echo "CONTRASEÑA ACTUAL ${password_actual}" | wc -c ) | bc )

        printf "${WHITE}〢 %-10s : ${GREEN}%0.9s ${WHITE}%${one_length}s\n" "PUERTO ACTUAL" "${puerto_actual}" '〢'
        printf "${WHITE}〢 %-10s : ${GREEN}%-${#password_actual}s ${WHITE}%${two_length}s\n" "CONTRASEÑA ACTUAL" "${password_actual}" '〢'
    
        if [[ ! -z "$(pidof obfs-server)" ]];then
            local tmp_str="SHADOWSOCKS-LIBEV SIMPLE-OBFS: ON"
            three_length=$(echo 60 - $(echo ${tmp_str} | wc -c ) | bc )
            printf "${WHITE}〢 %-10s : ${GREEN}%-3s ${WHITE}%${three_length}s\n" "SHADOWSOCKS-LIBEV SIMPLE-OBFS" "ON" '〢'
        else

            if [[ ! -z "$(pidof ss-server)" ]];then
                local tmp_str="SHADOWSOCKS-LIBEV: ON"
                three_length=$(echo 60 - $(echo ${tmp_str} | wc -c ) | bc )
                printf "${WHITE}〢 %-10s : ${GREEN}%-3s ${WHITE}%${three_length}s\n" "SHADOWSOCKS-LIBEV" "ON" '〢'
            else
                local tmp_str="SHADOWSOCKS-LIBEV:  OFF"
                three_length=$(echo 60 - $(echo ${tmp_str} | wc -c ) | bc )
                printf "${WHITE}〢 %-10s : ${RED}%-4s ${WHITE}%${three_length}s\n" "SHADOWSOCKS-LIBEV" "OFF" '〢'
            fi
        fi
        line_separator 60
    }
    show_info
    option_color "0" "VER CONFIGURACION URI"
    option_color "1" "CAMBIAR PUERTO"
    option_color "2" "CAMBIAR CONTRASEÑA"
    { #Check if simple-obfs is installed or is executing
        if [[ $simple_obfs_installed -eq 0 ]];then
            option_color "3" "ADMINISTRAR PLUGIN: simple-obfs"
        else
            option_color "3" "INSTALAR PLUGIN: simple-obfs"
        fi
    }
    
    if [[ $shadowsocks_is_running -eq 0 ]];then
        option_color "4" "REINICIAR SHADOWSOCKS-LIBEV"
        option_color "5" "DETENER SHADOWSOCKS-LIBEV"
        option_color "6" "DESINSTALAR SHADOWSOCKS-LIBEV"
        option_color "7" "VER ESTADO DE SHADOWSOCKS-LIBEV"
    else
        option_color "4" "INICIAR SHADOWSOCKS-LIBEV"
        option_color "5" "DESINSTALAR SHADOWSOCKS-LIBEV"
        option_color "6" "VER ESTADO DE SHADOWSOCKS-LIBEV"
    fi
    option_color "B" "MENU DE INSTALACION DE SOFTWARE"
    option_color "M" "MENU PRINCIPAL"
    option_color "E" "SALIR"

    ss_pid=$(pidof ss-server)
    obfs_server_pid=$(pidof obfs-server)
    run_obfs_server(){
        local obfs="$1"
        local bug_host="cloudflare.com"
        
        nohup ss-server -c /etc/shadowsocks-libev/config.json --plugin obfs-server --plugin-opts "obfs=$obfs" >/dev/null 2>&1 &
        extra_args="?plugin=$(python3 -c "import urllib.parse;print(urllib.parse.quote('obfs-local;obfs=${obfs};obfs-host=${bug_host}'))")"

        _config_uri
        if [[ $? -eq 0 ]];then
            info "Plugin obfs-server iniciado correctamente."
            sleep 1.5
        else
            error "Error al iniciar el plugin obfs-server."
            sleep 1.5
        fi
    }

    
    
    while true;do
        trap ctrl_c SIGINT
        prompt=$(date "+%x %X")
        read -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " option_shadowsocks
        case $option_shadowsocks in
            0) #VER CONFIGURACION URI
                _config_uri
                echo -e "${GREEN}${uri_shadowsocks}"
                ;;
            1)  # cambiar puerto
                {
                    while true;do
                        trap ctrl_c SIGINT SIGTERM
                        read -p "$(echo -e "${WHITE}[*] Ingrese el nuevo puerto: ${GREEN}")" new_port
                        if [[ -z $new_port ]]; then continue ; fi
                        check_if_port_is_open $new_port
                        if [[ $? -eq 0 ]];then ufw allow $new_port &>/dev/null; break ; else continue ; fi
                    done
                    echo -e "${WHITE}[*] Cambiando el puerto a ${GREEN}$new_port${WHITE}."
                    local tmp_file=$(mktemp)
                    jq '.server_port = "'$new_port'"'  /etc/shadowsocks-libev/config.json > $tmp_file 
                    mv $tmp_file /etc/shadowsocks-libev/config.json && chmod 644 /etc/shadowsocks-libev/config.json
                    _config_uri
                    bar "service shadowsocks-libev restart"
                    if [[ $? -eq 0 ]];then
                        info "Puerto ${GREEN}$new_port${WHITE} cambiado correctamente."
                        sleep 1.5
                    else
                        error "Error al cambiar el puerto."
                        sleep 1.5
                    fi
                    clear
                    cfg_shadowsocks


                }
                ;;
            2)  # cambiar password
                {
                    while true;do
                        trap ctrl_c SIGINT SIGTERM
                        read -p "$(echo -e "${WHITE}[*] Ingrese la nueva contraseña (random): ${GREEN}")" new_passwd
                        if [[ -z $new_passwd ]]; then
                            info "Generando contraseña aleatoria..."
                            new_passwd=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
                        fi
                        break
                    done
                    echo -e "${WHITE}[*] Cambiando la contraseña a ${GREEN}$new_passwd${WHITE}."
                    local tmp_file=$(mktemp)
                    
                    jq '.password = "'$new_passwd'"'  /etc/shadowsocks-libev/config.json > $tmp_file 
                    mv $tmp_file /etc/shadowsocks-libev/config.json && chmod 644 /etc/shadowsocks-libev/config.json
                    _config_uri
                    bar "service shadowsocks-libev restart"
                    if [[ $? -eq 0 ]];then
                        info "Contraseña ${GREEN}$new_passwd${WHITE} cambiada correctamente."
                        sleep 1.5
                    else
                        error "Error al cambiar la contraseña."
                        sleep 1.5
                    fi
                }
                read -p "$(echo -e "${WHITE}[*] Presione ENTER para continuar...")"
                clear
                cfg_shadowsocks
                ;;
            3) # instalar/administrar plugin
                {   
                    clear                            
                    echo -e "${BLUE}〢────────────〢 ${WHITE}SHADOWSOCKS-LIBEV | SIMPLE-OBFS${BLUE} 〢───────────〢"
                    
                    if [[ $simple_obfs_installed -eq 0 ]];then
                        if [[ ! -z "$obfs_server_pid" ]];then
                            option_color "1" "DETENER OBFS-SERVER"
                        else
                            option_color "1" "INICIAR OBFS-SERVER"
                        fi
                        option_color "2" "CAMBIAR OBFUSCACION ( HTTP/TLS )"
                        option_color "B" "MENU DE INSTALACION DE SOFTWARE"
                        option_color "M" "MENU PRINCIPAL"
                        option_color "E" "SALIR"
                        while true;do
                            prompt=$(date "+%x %X")
                            read -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " option_plugin
                            case $option_plugin in 
                                1 ) # INICIAR/DETENER OBFS-SERVER
                                    {   
                                        # detener obfs-server
                                        if [[ ! -z "$obfs_server_pid" ]];then
                                            killall ss-server &>/dev/null
                                            if [[ $? -eq 0 ]];then
                                                info "Obfs-server detenido correctamente."
                                            else
                                                error "Error al detener obfs-server."
                                            fi
                                        # iniciar obfs-server
                                        else
                                            killall ss-server &>/dev/null
                                            run_obfs_server "http"
                                        fi
                                    }
                                    clear
                                    cfg_shadowsocks
                                    ;;
                                2 ) # TLS/HTTP
                                    {
                                        info "Seleccione el tipo de obuscacion:"
                                        echo -e "${WHITE}[ ${BLUE}1${WHITE} ] ${GREEN}TLS${WHITE}"
                                        echo -e "${WHITE}[ ${BLUE}2${WHITE} ] ${GREEN}HTTP${WHITE}"
                                        while true;do
                                            read -p "$(echo -e "${WHITE}[*] Ingrese la opcion [1-2]: ${GREEN}")" option_obfs
                                            if [[ -z $option_obfs ]]; then continue ; fi
                                            if [[ $option_obfs -eq 1 ]];then
                                                info "Cambiando ofuscacion a TLS"
                                                run_obfs_server "tls"
                                                break
                                            elif [[ $option_obfs -eq 2 ]];then
                                                info "Cambiando ofuscacion a HTTP"
                                                run_obfs_server "http"
                                                break
                                            else
                                                continue
                                            fi
                                        done
                                    }
                                    clear
                                    cfg_shadowsocks
                                    ;;
                                
                                [Bb]) # menu de instalacion de software
                                    clear
                                    option_menu_software
                                    ;;
                                [Mm]) # menu principal
                                    clear
                                    fenix
                                    ;;
                                q|Q|e|E) # salir
                                    exit 0
                                    ;;
                                *) # opcion invalida
                                    continue
                                    ;;
                            esac
                        done
                    else
                        info "Plugin simple-obfs no se encuentra instalado"
                        read 
                    fi
                    


                    install_plugin() {
                        info 'Instalando plugin simple-obfs...'
                        local git_url='https://github.com/shadowsocks/simple-obfs'
                        local package_to_install=(build-essential autoconf libtool libssl-dev libpcre3-dev libev-dev asciidoc xmlto automake)
                        for i in "${package_to_install[@]}";do
                            bar "apt-get --no-install-recommends install -y $i"
                            if [[ $? -eq 0 ]];then
                                info "$i instalado correctamente."
                            else
                                error "Fallo al instalar $i."
                                if [[ $? -eq 130 ]];then exit 130 ; fi
                            fi
                        done
                        bar "git clone https://github.com/shadowsocks/simple-obfs.git /tmp/simple-obfs"
                        cd /tmp/simple-obfs
                        bar "git submodule update --init --recursive"
                        bar "./autogen.sh"
                        bar "./configure && make"
                        bar "make install"
                        if [[ $? != 0 ]];then
                            error "Fallo al instalar simple-obfs."
                            if [[ $? -eq 130 ]];then exit 130 ; fi
                        else
                            info "Plugin simple-obfs instalado y habilitado correctamente."
                            ss-server -c /etc/shadowsocks-libev/config.json --plugin obfs-server --plugin-opts "obfs=http" &> /dev/null &
                        fi
                        rm -rf /tmp/simple-obfs
                    }
                }
                ;;
            4) # reiniciar/iniciar shadowsocks
                {
                    if [[ $shadowsocks_is_running -eq 0 ]];then
                        killall ss-server &>/dev/null
                        bar "service shadowsocks-libev restart"
                        if [[ $? -eq 0 ]];then
                            sleep 1.5
                            cfg_shadowsocks
                        else
                            sleep 1.5
                            cfg_shadowsocks
                        fi
                    else
                        killall ss-server &>/dev/null
                        bar "service shadowsocks-libev start"
                        if [[ $? -eq 0 ]];then
                            sleep 1.5
                            cfg_shadowsocks
                        else
                            sleep 1.5
                            cfg_shadowsocks
                        fi
                    fi
                }
                ;;
            5)  # detener/desinstalar shadowsocks
                {
                    if [[ $shadowsocks_is_running -eq 0 ]];then
                        killall ss-server &>/dev/null
                        bar "service shadowsocks-libev stop"
                        if [[ $? -eq 0 ]];then
                            sleep 1.5
                            cfg_shadowsocks
                        else
                            sleep 1.5
                            cfg_shadowsocks
                        fi
                    else
                        killall ss-server &>/dev/null
                        unistall_shadowsocks
                        sleep 1.5
                        clear
                        option_menu_software
                    fi
                }
                ;;
            6)  # desinstalar/ver estado shadowsocksk
                {   
                    if [[ $shadowsocks_is_running -eq 0 ]];then
                        killall ss-server &>/dev/null
                        unistall_shadowsocks
                        sleep 1.5
                        option_menu_software
                    else
                        service shadowsocks-libev status
                        sleep 1.5
                        cfg_shadowsocks
                    fi
                }
                ;;
            7) # ver estado de shadowsocks
                service shadowsocks-libev status
                ;;

            "cls" | "CLS")
                clear
                cfg_shadowsocks
                ;;
            [bB])
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

cfg_openvpn(){
    trap ctrl_c SIGINT SIGTERM
    clear
    [[ ! -f "/etc/openvpn/server.conf" ]] && {
        error "No se encuentra el archivo de configuracion de openvpn."
        info "Es recomendable resintarlo."
        read -p "$(echo -e "${WHITE}[*] Desea reinstalarlo? [Y/n]: ${GREEN}")" reinstall_openvpn
        if [[ $reinstall_openvpn =~ ^[Yy]$ ]];then
            install_openvpn
        else
            exit 0
        fi
    }
    local ovpn_port_actually=$(cat /etc/openvpn/server.conf | grep -E 'port [0-9]{0,}' | grep -Eo '[0-9]{4,5}' | tr "\n" ' ')
    local ovpn_proto_actually=$(cat /etc/openvpn/server.conf | grep -E 'proto [a-zA-Z]{0,}' | grep -Eo '[a-zA-Z]{0,}' | tr "\n" ' ' | cut -d " " -f2)
    local oppenvpn_is_running=$(ps -ef | grep openvpn | grep -v grep | wc -l)
    echo -e "${BLUE}〢─────────────────〢${WHITE}CONFIGURANDO OPENVPN${BLUE}〢───────────────────〢"
    
    show_info(){
        local one_length two_length
        one_length=$(echo 60 - $(echo "PUERTO ${ovpn_port_actually}" | wc -c ) | bc )
        two_length=$(echo 60 - $(echo "PROTOCOLO ${ovpn_proto_actually}" | wc -c ) | bc )
        if [[ $oppenvpn_is_running -eq 1 ]];then
            ovpn_status="[ EN EJECUCION ]"
            stat_color=${GREEN}
        else
            ovpn_status="[ DETENIDO ]"
            stat_color=${RED}
        fi
        three_length=$(echo 60 - $(echo "OPENVPN ${ovpn_status}" | wc -c ) | bc )

        printf "${WHITE}〢 %-6s : ${GREEN}%5s ${WHITE}%${one_length}s\n" "PUERTO" "${ovpn_port_actually}" '〢'
        printf "${WHITE}〢 %-9s : ${GREEN}%-${#two_length}s ${WHITE}%${two_length}s\n" "PROTOCOLO" "${ovpn_proto_actually}" '〢'
        printf "${WHITE}〢 %-6s : ${stat_color}%-${#three_length}s ${WHITE}%${three_length}s\n" "OPENVPN" "${ovpn_status}" '〢'
        line_separator 60
    
    }
    show_info
    option_color "1" "ADICIONAR UN PUERTO"
    option_color "2" "REMOVER UN PUERTO"
    option_color "3" "CAMBIAR PROTOCOLO (tcp/udp)"
    option_color "4" "CAMBIAR SERVIDORES DNS"

    if [[ $oppenvpn_is_running -eq 0 ]];then
        option_color "5" "INICIAR OPENVPN"
        option_color "6" "DESINSTALAR OPENVPN"
        option_color "7" "VER ESTADO OPENVPN"
    else
        option_color "5" "REINICIAR OPENVPN"
        option_color "6" "DETENER OPENVPN"
        option_color "7" "VER ESTADO OPENVPN"
        option_color "8" "DESINSTALAR OPENVPN"
    fi
    option_color "B" "MENU DE INSTALACION DE SOFTWARE"
    option_color "M" "MENU PRINCIPAL"
    option_color "E" "SALIR"

    actually_dns_primary=$(cat /etc/openvpn/server.conf | grep -Eo 'DNS .*"' | cut -d " " -f 2 | sed -e 's/"/ /g')

    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " option_vpn
        case $option_vpn in
            1) # AGREGAR UN PUERTO
                {
                    port_input
                    ovpn_new_port=${puertos_array[@]} && unset puertos_array
                    info "Agregando puerto $ovpn_new_port"
                    # delete line with port
                    sed -i '/port/d' /etc/openvpn/server.conf
                    # add new port
                    sed  -i "1i port ${ovpn_port_actually} ${ovpn_new_port}" /etc/openvpn/server.conf
                    if [[ $? -eq 0 ]];then
                        info "Puerto $ovpn_new_port agregado correctamente."
                    else
                        error "Error al agregar el puerto $ovpn_new_port."
                    fi

                }
                clear
                cfg_openvpn
                ;;
            2) # REMOVER UN PUERTO
                {
                    info 'Seleccione el puerto a eliminar:'
                    local count=0
                    ovpn_port_array=($ovpn_port_actually)
                    for i in ${ovpn_port_actually[@]}; do
                        count=$((count+1))
                        echo -e "  ${WHITE}[ ${BLUE}$count${WHITE} ] ${GREEN}$i${WHITE}"
                    done
                    while true;do
                        read -p "$(echo -e "${WHITE}[*] ${BLUE}Seleccione una opcion [1-${count}]${WHITE} : ")" option_port_del
                        if [[ -z $option_port_del ]];then continue ; fi
                        if [[ $option_port_del -ge 1 && $option_port_del -le $count ]];then break ; else continue ; fi
                    done
                    ovpn_port_del=${ovpn_port_array[$option_port_del-1]}
                    sed  -i "s/${ovpn_port_del}/ /g" /etc/openvpn/server.conf
                    if [[ $? -eq 0 ]];then
                        info "Puerto $ovpn_port_del eliminado correctamente."
                    else
                        error "Error al eliminar el puerto $ovpn_port_del."
                    fi
                    sleep 1.5
                    cfg_openvpn
                }
                clear
                cfg_openvpn
                ;;
            3) # CAMBIAR PROTOCOLO (tcp/udp)
                {
                     info "Seleccione el protocolo:"
                     local list_port_array=(tcp udp)
                     echo -e "${WHITE}[ ${BLUE}1${WHITE} ] ${GREEN}TCP${WHITE}"
                     echo -e "${WHITE}[ ${BLUE}2${WHITE} ] ${GREEN}UDP${WHITE}"
                     while true;do
                        read -p "$(echo -e "${BLUE}[*] Ingrese la opcion [1-2]: ${GREEN}")" proto
                        if [[ -z $proto ]];then continue ; fi
                        if [[ $proto -ge 1 && $proto -le 2 ]];then break ; else continue ; fi
                    done
                    ovpn_proto_new=${list_port_array[$proto-1]}
                    sed -i "s/proto ${ovpn_proto_actually}/proto ${ovpn_proto_new}/g" /etc/openvpn/server.conf
                        if [[ $? -eq 0 ]];then
                            info "Protocolo cambiado a ${ovpn_proto_new}."
                        else
                            error "Error al cambiar el protocolo."
                        fi
                }
                sleep 1.5
                cfg_openvpn
                ;;
            4) # CAMBIAR SERVIDORES DNS
                {
                    IFS=' ' read -ra dns_ <<< $(cat /etc/openvpn/server.conf | grep -Eo 'DNS .*"' | cut -d " " -f 2 | sed -e 's/"//g' | tr '\n' ' ')
                    info "Servidores DNS primario: ${dns_[0]}"
                    info "Servidores DNS secundario: ${dns_[1]}"
                    
                    # Si,el codigo se repite.Pero solo son dos veces.
                    # Y ya me aburri de hacerlo. :v
                    while true;do #DNS PRIMARIO
                        read -p "$(echo -e "${WHITE}[*] Servidor dns primario: ")" dns_one
                            if [[ -z $dns_one ]];then continue ; fi
                            if [[ $dns_one =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                                break
                            else
                                error "Servidor dns ($dns_one) no es una direccion ipv4 valida."
                                continue
                            fi
                    done

                    while true;do #DNS SECUNDARIOk
                        read -p "$(echo -e "${BLUE}[*] Servidor dns secundario: ")" dns_two
                        if [[ -z $dns_two ]];then continue ; fi
                        if [[ $dns_two =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];then
                            break
                        else
                            error "Servidor dns ($dns_two) no es una direccion ipv4 valida."
                            continue
                        fi
                    done

                    #Bueno ahora toca cambiar las dns,dentro del archivo
                    sed -i "s/${dns_[0]}/${dns_one}/g" /etc/openvpn/server.conf &> /dev/null
                    sed -i "s/${dns_[1]}/${dns_two}/g" /etc/openvpn/server.conf &> /dev/null
                    if [[ $? -eq 0 ]];then
                        info "DNS cambiados correctamente."
                    else
                        error "Error al cambiar los DNS."
                    fi

                }
                sleep 1.5
                cfg_openvpn
                ;;
            5) # INICIAR/REINICIAR OPENVPN
                {
                 if [[ $oppenvpn_is_running -eq 0 ]];then
                    bar "systemctl start openvpn@server"
                 else
                    bar "systemctl restart openvpn@server"
                 fi
                }
                sleep 1.5
                cfg_openvpn
                ;;
            6) # DETENER/DESINSTALAR OPENVPN
                {
                    if [[ $oppenvpn_is_running -eq 0 ]];then
                        remove_openvpn
                    else
                        bar "systemctl stop openvpn@server"
                        sleep 1.5
                        cfg_openvpn
                    fi
                }
                clear
                option_menu_software
                ;;
            7) # DESINSTALAR/VER ESTADO OPENVPN
                service openvpn@server status
                ;;
            8) # REMOVER OPENVPN    
                remove_openvpn
                ;;
            "cls" | "CLS")
                clear
                cfg_openvpn
                ;;
            [bB])
                option_menu_software
                ;;
            [mM])
                fenix
                ;;
            q|Q|e|E)
                exit 0
                ;;
        esac
    done


    
}


cfg_python3_proxy(){
    trap ctrl_c SIGINT SIGTERM
    clear
    echo -e "${BLUE}〢─────────────────〢${WHITE} CONFIGURANDO PYSOCKS ${BLUE}〢──────────────────〢${WHITE}"
    local config_file="${user_folder}/FenixManager/py-socks.conf"
    [[ ! -f $config_file ]] && touch $config_file 2>/dev/null
    local pysocks_is_actived=$(systemctl is-active fenixmanager-pysocks &>/dev/null;echo $?)
    if [[ "$pysocks_is_actived" -eq 0 ]];then local pysocks_pid=$(systemctl show --property MainPID --value fenixmanager-pysocks); fi

    show_info(){
        local color_1 color_2 color_3
        if [[ ! $pysocks_is_actived -eq 0 ]];then
            color_1="${RED}"
            color_2="${RED}"
            color_3="${RED}"
        else
            color_1="${GREEN}"
            color_2="${BLUE}"
            color_3="${YELLOW}"
        fi
        local custom_quantity=$(grep -E "^[CUSTOM#[0-9]{0,9}]" ${config_file} 2>/dev/null| cut -d# -f 2 | tr "]" " " | xargs)
        local conf_key=(accept connect custom_response)
        printf "${WHITE}〢 ${color_1}%-10s ${color_2}%26s ${color_3}%20s ${WHITE}%$((60 - 10 - 26 - 20))s\n" "ACCEPT" "RESPONSE CODE" "CONNECT" '〢'
        
        if [[ -z "${custom_quantity}" ]];then
            [[ -f "${config_file}" ]] || touch "${config_file}"
            line_separator 60
            return 0
        else
            for count in ${custom_quantity};do
                local array_cfg=()
                for key in ${conf_key[@]};do
                    local sed_string="/^\[CUSTOM#${count}]/ { :l /^${key}[ ]*=/ { s/[^=]*=[ ]*//; p; q;}; n; b l;}"
                    local ${key}="$(sed -n "${sed_string}" "${config_file}")"
                    if [[ ${key} == "accept" ]];then
                        # re check if port is open
                        local is_open=$(ss -lptn "sport = :${!key}" | grep "${!key}" -c)
                        if [[ $is_open -eq 0 ]];then local color_1=${RED} ; local color_2=${RED} ; local color_3=${RED}; fi
                    fi
                    if [[ "${key}" == *"custom_response"* ]];then
                        local ${key}="$(grep -E "HTTP/[0-9]\.?[0-9]? [0-9]{1,9}" -o <<< ${!key})"
                    fi
                    array_cfg+=("${!key}")
                done
                printf "${WHITE}〢 ${color_1}%5s ${color_2}%31s ${color_3}%20s ${WHITE}%$((60 - 5 - 31 - 20))s\n" "${array_cfg[0]}" "${array_cfg[2]}" "${array_cfg[1]}" '〢'
            done
        fi
        line_separator 60
        
    }
    show_info

    option_color 1 "AGREGAR UN PUERTO"
    option_color 2 "ELIMINAR UN PUERTO"
    option_color 3 "VER ESTADO DE PYSOCKS"
    if [[ "$pysocks_is_actived" -eq 0 ]];then
    option_color 4 "DETENER PYSOCKS"
        option_color 5 "REINICIAR PYSOCKS"
        option_color 6 "${RED}DESHABILITAR PYSOCKS"
    else
        option_color 4 "${WHITE}INICIAR PYSOCKS"
        option_color 5 "${RED}DESHABILITAR PYSOCKS"
    fi
    option_color B "MENU DE CONFIGURACION"
    option_color M "MENU PRINCIPAL"
    option_color E "SALIR"  

    while true;do
        trap ctrl_c SIGINT
        prompt=$(date "+%x %X")
        read -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " option
        case $option in
            1) # AGREGAR PUERTO
                {
                    while true;do
                        port_input
                        local port="${puertos_array[0]}" && unset puertos_array
                        local port_in_file=$(grep -E "^accept=[0-9]{1,6}" "${user_folder}/FenixManager/py-socks.conf" 2>/dev/null| cut -d= -f2 | grep -c -w "${port}")
                        [[ $port_in_file -ne 0 ]] && {
                            error "El puerto existe en el archivo de configuracion."
                            continue
                        } || break
                    done
                    redirect_to_service "pysocks"
                    local port_to_redirect="${SERVICE_REDIRECT}" && unset SERVICE_REDIRECT
                    local number_of_custom_config=($(grep -Eo "#[0-9]{1,}" ${config_file} | cut -d# -f2 | xargs ))
                    [[ -z "${number_of_custom_config}" ]] && number_of_custom_config=0 || number_of_custom_config="$((${number_of_custom_config[-1]}+1))"
                    
                    select_status_code(){
                    
                        while true;do
                            read -p "$(echo -e "${BLUE}[*] Seleccione el codigo de estado HTTP  [100-599] : ")" status_code
                            if [[ -z "$status_code" ]];then continue ; fi
                            if [[ $status_code =~ ^[0-9]+$ ]];then
                                if [[ $status_code -ge 100 && $status_code -le 599 ]];then
                                    break
                                fi
                            fi
                        done
                    }
                    select_string_msg(){
                        local array_colors=(RED GREEN BLUE YELLOW MAGENTA)
                        local html_colors=("#ff3333" "#0500ff" "#0cff00" "#ffef00" "#ff0078" "#ffffff" "#000000")
                        info "${RED}No ${WHITE}utilizar: codigos ${RED}html${WHITE}, ${RED}emojis${WHITE} o cualquier otro caracter ${RED}invalido${WHITE}."
                        read -p "$(echo -e "${WHITE}[*] Escriba el texto de conexion : ")" string_banner
                        string_banner="${string_banner^^}"
                        if [[ -z "$string_banner" ]];then
                            string_banner="<font color=\"${html_colors[0]}\"><b>FenixManager<b></font>"
                        else
                            info 'Seleccione unos de los colores disponibles:'
                            echo -e "\t${WHITE}[ 0 ] ${RED}${string_banner}"
                            echo -e "\t${WHITE}[ 1 ] ${GREEN}${string_banner}"
                            echo -e "\t${WHITE}[ 2 ] ${BLUE}${string_banner}"
                            echo -e "\t${WHITE}[ 3 ] ${YELLOW}${string_banner}"
                            echo -e "\t${WHITE}[ 4 ] ${MAGENTA}${string_banner}"
                            echo -e "\t${WHITE}[ 5 ] ${WHITE}${string_banner}"
                            echo -e "\t${WHITE}[ 6 ] \e[30;107m${string_banner}${END_COLOR} ( Solamente negro. El fondo es blanco por obvias razones )"
                            read -p "$(echo -e "${BLUE}[*] opcion [1-7] : ${END_COLOR}")" color_code
                            if [[ -z "$color_code" ]];then color_code=1 ; fi
                            if [[ $color_code =~ ^[0-9]+$ ]];then
                                if [[ $color_code -ge 1 && $color_code -le 7 ]];then
                                    string_banner="<font color=\"${html_colors[${color_code}]}\"><b>${string_banner}<b></font>"
                                fi
                            fi
                        fi
                    }
                    select_status_code
                    select_string_msg
                    local base_response="HTTP/1.1 ${status_code} ${string_banner}[crlf]Content-length: 0[crlf][crlf]"
                    [[ "${SERVICE_NAME}" == "dropbear" || "${SERVICE_NAME}" == "ssh" ]] && {
                        local connection_type="SSH"
                    } || {
                        local connection_type="OPENVPN"
                    }
                    local base_cfg="[CUSTOM#${number_of_custom_config}]\naccept=${port}\nconnect=127.0.0.1:${port_to_redirect}\ncustom_response=${base_response}\nconnection_type=${connection_type}\n"
                    echo -e "${base_cfg}" >> "${config_file}"
                    local service_status=$(systemctl status fenixmanager-pysocks &>/dev/null;echo $?)
                    if [[ $service_status -eq 0 ]];then
                        bar "systemctl reload fenixmanager-pysocks"
                    else
                        bar "systemctl restart fenixmanager-pysocks"
                    fi
                    if [[ $? -eq 0 ]];then
                        info "El puerto ${port} se ha agregado correctamente."
                    else
                        error "Fallo al agregar el puerto ${port}."
                        pysocks_del_port ${port}
                    fi
                }
                sleep 4
                cfg_python3_proxy
                ;;
            2) # ELIMINAR PUERTO
                pysocks_del_port 
                cfg_python3_proxy
                ;;
            3) systemctl status fenixmanager-pysocks ;;
            4) # INICIAT/DETENER PYSOCKS
                [[ "$pysocks_is_actived" -eq 0 ]] && bar "systemctl stop fenixmanager-pysocks" || bar "systemctl start fenixmanager-pysocks"
                sleep 2
                cfg_python3_proxy
                ;;
            5) # REINICIAR/DESHABILIAR PYSOCKS
                [[ "$pysocks_is_actived" -eq 0 ]] && bar "systemctl restart fenixmanager-pysocks"  || bar "systemctl disable fenixmanager-pysocks"
                sleep 3
                cfg_python3_proxy
                ;;
            6) #DESHABILITAR PYSOCKS
                bar "systemctl disable fenixmanager-pysocks"
                sleep 3
                cfg_python3_proxy
                ;;
            cls|CLS)
                clear
                cfg_python3_proxy
                ;;
            [bB]) option_menu_software ;;
            [Mm]) fenix ;;
            q|Q|e|E) exit 0 ;;
        esac
    done

}

cfg_slowdns(){
    trap ctrl_c SIGINT SIGTERM
    clear
    echo -e "${BLUE}〢─────────────────〢${WHITE} CONFIGURANDO SLOWDNS ${BLUE}〢─────────────────〢"
    local slowdns_running=$(pgrep slowdns &>/dev/null;echo $?)
    if [[ $slowdns_running -ne 0 ]];then install_slowdns ; fi
    local pub_key=$(cat "${user_folder}/FenixManager/slowdns_pubkey" 2>/dev/null)
    show_info(){
        # 66
        if [[ $slowdns_running -eq 1 ]];then
            printf "${WHITE}〢 ${RED}%-10s ${RED}%10s ${WHITE}%43s\n" "SLOWDNS ESTA" "DESACTIVADO" '〢'
        else
            local protocolo port key_file redirect_to
            local slowdns_pid=$(pgrep slowdns)
            local process_argv=$(cat "/proc/${slowdns_pid}/cmdline" 2>/dev/null | sed -e 's/\x00/ /g'; echo )
            IFS=' ' read -r -a array_argv <<< "${process_argv}"
            local protocolo=${array_argv[1]//-}
            local port=${array_argv[2]//:}
            local name_server=${array_argv[5]}
            local connect_to=${array_argv[6]}
            # 12 
            printf "${WHITE}〢 %-10s : ${GREEN}%2s ${WHITE}%45s\n" "PROTOCOLO" "${protocolo^^}" '〢'
            printf "${WHITE}〢 %-7s : ${GREEN}%32s ${WHITE}%19s\n" "PUERTO" "PREROUTING :${port}/udp -> :53/udp" '〢'
            printf "${WHITE}〢 %-14s : ${GREEN}%10s ${WHITE}%$((44 - ${#name_server}))s\n" "NameServer(NS)" "${name_server}" '〢'
            printf "${WHITE}〢 %-8s : ${GREEN}%10s ${WHITE}%38s\n" "CONNECT" "${connect_to}" '〢'
        fi
        line_separator 60
    }
    show_info

    option_color 1 "${RED}DETENER${WHITE} SLOWDNS"
    option_color 2 "MOSTRAR CLAVE PUBLICA   "
    option_color 'B' "MENU DE INSTALACION DE SOFTWARE"
    option_color 'M' "MENU PRINCIPAL"
    option_color 'E' "SALIR"    
    while true;do
        trap ctrl_c SIGINT
        prompt=$(date "+%x %X")
        read -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " option
        case $option in
            1) #DETENER SLOWDNS
                killall slowdns 2>/dev/null
                rm "${user_folder}/FenixManager/slowdns_pubkey" 2>/dev/null
                fenix
                ;;
            2) [[ -z "${pub_key}" ]] && error "No se ha encontrado la clave publica." || echo -e "${pub_key}" ;;
            [bB]) option_menu_software ;;
            [Mm]) fenix ;;
            q|Q|e|E) exit 0 ;;
        esac
    done

    
}

cfg_ssh_dropbear(){
    trap ctrl_c SIGINT SIGTERM
    clear
    
    echo -e "${BBLUE}〢────────────────〢 ${WHITE}CONFIGURANDO SSH / DROPBEAR${BBLUE} 〢───────────〢${WHITE}"
    
    local ssh_file="/etc/ssh/sshd_config"
    local dropbear_file="/etc/default/dropbear"
    local dropbear_is_installed
    
    show_info(){
        local ssh_ports=$(grep "^Port" ${ssh_file} | cut -d' ' -f2 | tr "\n" ' ')
        local ssh_is_running=$(pgrep sshd &>/dev/null;echo $?)
        local ssh_banner=$(grep "^Banner" ${ssh_file} | cut -d' ' -f2 | sed -e "s|${user_folder}|~|g")
        # ! OPENSSH
        if [[ "${ssh_is_running}" -eq 0 ]];then
            ssh_is_running="[ ACTIVADO ]"
            color_1="${GREEN}"
        else
            ssh_is_running="[ DESACTIVADO ]"
            color_1="${RED}"
        fi
        
        printf "${WHITE}〢 %8s ${color_1}%${#ssh_is_running}s %$((60 - 12 - ${#ssh_is_running}))s ${WHITE}〢\n" "OPENSSH:" "${ssh_is_running}"
        printf "${WHITE}〢 %8s ${color_1}%${#ssh_ports}s ${WHITE}%$((60 - 12 - ${#ssh_ports} | bc ))s 〢\n" "PUERTOS:" "${ssh_ports}"
        printf "${WHITE}〢 %7s ${color_1}%${#ssh_banner}s ${WHITE}%$((60 - 11 - ${#ssh_banner} | bc ))s 〢\n" "BANNER:" "${ssh_banner}"
        
        # ! DROPBEAR
        line_separator 60
        package_installed "dropbear" && {
            dropbear_is_installed=0
            local dropbear_is_runing=$(pgrep dropbear &>/dev/null;echo $?)
            if [[ "${dropbear_is_runing}" -eq 0 ]];then
                local drop_str="[ EN EJECUCION ]"
                local color_1="${GREEN}"
            else
                local drop_str="[ DETENIDO ]"
                local color_1="${RED}"
            fi
            dropbear_ports=$(grep -o "^DROPBEAR_EXTRA_ARGS=.*"  ${dropbear_file} | awk '{split($0,a,"="); print a[2]}' | sed -e "s/'/ /g" | sed "s/-p/ /g" | xargs)
            dropbear_ports+=" $(grep "^DROPBEAR_PORT=.*" /etc/default/dropbear | awk '{split($0,a,"="); print a[2]}')"
            local dropbear_banner=$(grep -o "^DROPBEAR_BANNER=.*"  ${dropbear_file} | awk '{split($0,a,"="); print a[2]}' | sed -e "s/'/ /g" | sed "s|${user_folder}|~|g" | xargs)
        
            # ! dropbear status
            printf "${WHITE}〢 %9s ${color_1}%${#drop_str}s ${WHITE} %$((60 - 10 - ${#drop_str} ))s\n" "DROPBEAR:" "${drop_str}" '〢'
            [ -z "${dropbear_ports}" ] && dropbear_ports="No se pudieron obtener los puertos."
            # ! dropbear ports
            printf "${WHITE}〢 %8s ${color_1}%${#dropbear_ports}s ${WHITE}%$((60 - 12 - ${#dropbear_ports} | bc))s 〢\n" "PUERTOS:" "${dropbear_ports}"
            # ! dropbear banner
            printf "${WHITE}〢 %7s ${GREEN}%${#dropbear_banner}s ${WHITE}%$((60 - 11 - ${#dropbear_banner} | bc ))s 〢\n" "BANNER:" "${dropbear_banner}"
            
        } || {
            dropbear_is_installed=1
            printf "${WHITE}〢 %9s ${RED}%16s ${WHITE} %$((60 - 10 - 16 ))s\n" "DROPBEAR:" "[ NO INSTALADO ]" '〢'
        }
        line_separator 60
    }
    show_info
    [[ ${dropbear_is_installed} -eq 0 ]] && {
        option_color 1 "AGREGAR PUERTOS EN DROPBEAR"
        option_color 2 "ELIMINAR PUERTOS EN DROPBEAR"
    } || {
        option_color 1 "INSTALAR DROPBEAR"
        option_color 2 "ELIMINAR PUERTOS EN OPENSSH ( SSH )"
    }
    option_color 3 "AGREGAR PUERTOS A OPENSSH ( SSH )"
    option_color 4 "CAMBIAR BANNER"
    option_color 5 "REINICIAR OPENSSH / DROPBEAR"
    [[ ${dropbear_is_installed} -eq 0 ]] && {
        option_color 6 "VER ESTADO DE DROPBEAR"
        option_color 7 "ELIMINAR PUERTO OPENSSH ( SSH )"
        }
    option_color 'B' "MENU DE INSTALACION DE SOFTWARE"
    option_color 'M' "MENU PRINCIPAL"
    option_color 'E' "SALIR"

    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " opt
        case $opt in 
            1) # AGREGAR PUERTOS/INSTALAR DROPBEAR
                [[ ${dropbear_is_installed} -eq 0 ]] && { # ADD PORT
                    port_input
                    local dropbear_new_port=${puertos_array[@]} && unset puertos_array
                    local dropbear_extra_args=$(grep -o "^DROPBEAR_EXTRA_ARGS=.*"  ${dropbear_file} | awk '{split($0,a,"="); print a[2]}' | sed -e "s/'/ /g" | xargs)
                    for port in ${dropbear_new_port[@]};do dropbear_extra_args+=" -p ${port}" ; done
                    sed -i "s|^DROPBEAR_EXTRA_ARGS=.*|DROPBEAR_EXTRA_ARGS='${dropbear_extra_args}'|g" ${dropbear_file}
                    bar "systemctl restart dropbear"
                    info "Puerto ${dropbear_new_port[@]} agregado correctamente."
                    sleep 2
                } || { # INSTALL DROPBER
                    echo "/bin/false" >> /etc/shells # add /bin/false to shells, and prevent dropbear reject user with invalid shell
                    bar "apt-get install dropbear -y"
                    [[ $? -ne 0 ]] && {
                        error "No se pudo instalar dropbear."
                        sleep 2
                    }
                    info "Por defecto, drobear escuchara en el puerto 143"
                    info "Luego de instalar, puede agregar/quitar los puertos."
                    ufw allow 143/tcp &>/dev/null
                    local drop_cfg="NO_START=0\nDROPBEAR_PORT=143\nDROPBEAR_EXTRA_ARGS=''\nDROPBEAR_BANNER='${user_folder}/FenixManager/banner/fenix.html'\nDROPBEAR_RECEIVE_WINDOW=65536"
                    echo -e "${drop_cfg}" > "${dropbear_file}"
                    bar "service dropbear restart"
                    sleep 2
                }
                cfg_ssh_dropbear
                ;;
            2) # ELIMINAR PUERTOS DROPBEAR/OPENSSH
                [[ ${dropbear_is_installed} -eq 0 ]] && {
                    info "143, es el puerto por defecto de dropbear. No se puede eliminar." 
                    local dropbear_extra_ports=$(grep -o "^DROPBEAR_EXTRA_ARGS=.*"  ${dropbear_file} | awk '{split($0,a,"="); print a[2]}' | sed -e "s/'/ /g" | sed "s/-p/ /g" | xargs)
                    IFS=" " read -r -a ports_array <<< $dropbear_extra_ports
                    for ((i=0;i<${#ports_array[@]};i++));do
                        local port=${ports_array[$i]}
                        echo -e "\t${WHITE}[ ${BLUE}${i}${WHITE} ] ${GREEN}${port}${WHITE}"
                    done
                    while true;do
                        trap ctrl_c SIGINT SIGTERM
                        read -r -p "$(echo -e "${WHITE}[*] Opcion : ")" port_index
                        if [[ ${port_index} -ge 0 && ${port_index} -lt ${#ports_array[@]} ]];then
                            break
                        else
                            error "Opcion invalida."
                            continue
                        fi
                    done
                    local port_to_del=${ports_array[$port_index]}
                    local str_to_del="-p ${port_to_del}"
                    local dropbear_extra_args_from_file=$(grep -o "^DROPBEAR_EXTRA_ARGS=.*"  ${dropbear_file} | awk '{split($0,a,"="); print a[2]}' | sed -e "s/'/ /g" | xargs)
                    sed -i "s|^DROPBEAR_EXTRA_ARGS=.*|DROPBEAR_EXTRA_ARGS='${dropbear_extra_args_from_file//$str_to_del/}'|g"  ${dropbear_file}
                    bar "systemctl restart dropbear"
                    info "Puerto ${port_to_del} eliminado."
                } || {
                    # ELIMINAR PUERTOS SSH
                    del_openssh_port
                }
                sleep 2
                cfg_ssh_dropbear
                ;;
            3) # AGREGAR PUERTOS OPENSSH
                port_input
                local ssh_new_port=${puertos_array[@]} && unset puertos_array
                for port in ${ssh_new_port[@]};do
                    echo "Port ${port}" >> "${ssh_file}"
                done
                bar "service ssh restart"
                info "Puerto ${ssh_new_port[@]} agregado correctamente."
                sleep 4
                cfg_ssh_dropbear
                ;;
            4) # CAMBIAR BANNER
                # ! SELECT OPT BANNER
                local fenixbanner='<br><strong style="color:#0066cc;font-size: 30px;">〢 ────────────────────────〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Script: </strong><strong style="color:#ff0000;font-size: 30px;">FenixManager</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Version: </strong><strong style="color:#ff0000;font-size: 30px;">replace_version</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Dev: </strong><strong style="color:#ff0000;font-size: 30px;">@M1001_byte</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Github: </strong><strong style="color:#ff0000;font-size: 30px;">github.com/M1001-byte/FenixManager</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Telegram: </strong><strong style="color:#ff0000;font-size: 30px;">@M1001-byte</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Telegram: </strong><strong style="color:#ff0000;font-size: 30px;">@Mathiue1001</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#0066cc;font-size: 30px;">〢 ────────────────────────〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢Gracias por utilizar FenixManager!〢</strong>'
                change_banner(){
                    # find banner line number in ssh config
                    local banner_file="${1}"                    
                    local banner_size=$(wc -c < "${banner_file}")
                    if [[ ${banner_size} -gt 2000 ]];then
                        error "El banner supera los 2000 bytes ( 2 KB ). Limite impuesto por dropbear."
                        rm -f "${banner_file}"
                        return 1
                    fi
                    local ssh_banner_line=$(grep -n "^Banner" ${ssh_file} | cut -d: -f1)
                    local dropbear_banner_line=$(grep -n "^DROPBEAR_BANNER" ${dropbear_file} | cut -d: -f1)

                    # ! OPENSSH
                    [[ -z ${ssh_banner_line} ]] && {
                        echo "Banner ${banner_file}" >> ${ssh_file}
                    } || {
                        sed -i "${ssh_banner_line}s|^Banner.*|Banner ${banner_file}|g" ${ssh_file}
                    }
                    bar "service ssh restart"
                    # ! DROPBEAR
                    [[ -z ${dropbear_banner_line} ]] && {
                        echo "DROPBEAR_BANNER='${banner_file}'" >> ${dropbear_file}
                    } || {
                        sed -i "${dropbear_banner_line}s|^DROPBEAR_BANNER=.*|DROPBEAR_BANNER='${banner_file}'|g" ${dropbear_file}
                    }
                    bar "service dropbear restart"
                }
                banner_select() {
                    echo -e "${WHITE}[ ${GREEN}1${WHITE} ] ${WHITE}Cargar banner desde un archivo${WHITE}"
                    echo -e "${WHITE}[ ${GREEN}2${WHITE} ] ${WHITE}Cargar banner desde una URL${WHITE}"
                    echo -e "${WHITE}[ ${GREEN}3${WHITE} ] ${WHITE}Copiar banner de un servidor ssh${WHITE}"
                    echo -e "${WHITE}[ ${GREEN}4${WHITE} ] ${WHITE}Introducir el banner${WHITE}"
                    local banner_option
                    until [[ ${banner_option} =~ ^[1-4]$ ]];do
                        trap ctrl_c SIGINT SIGTERM
                        read -r -p "$(echo -e "${WHITE}[*] Opcion : ")" banner_option
                    done
                    
                    case $banner_option in 
                        1 ) # ! LOAD BANNER FROM FILE
                            list_banners && local banner_file="${BANNER_FILE}" && unset BANNER_FILE
                            change_banner "${banner_file}"
                            ;;
                        2 ) # ! LOAD BANNER FROM URL
                            info "Tenga en cuenta que, todo el contenido que devuelve la URL sera usado como banner."
                            info "Es recomendable que el contenido sea solamente texto plano."
                            read -r -p "$(echo -e "${WHITE}[*] URL : ")" banner_url
                            read -r -p "$(echo -e "${WHITE}[*] Nombre del archivo : ")" banner_file
                            banner_file="${user_folder}/FenixManager/banner/${banner_file// /_}"
                            if wget -q "${banner_url}" -O "${banner_file}";then
                                change_banner "${banner_file}"
                            else
                                error "No se pudo descargar el banner."
                                info "Compruebe su conexion a internet o firewall."
                                exit 1
                            fi
                            ;;
                        3 ) # ! COPY BANNER FROM SSH SERVER
                            package_installed "sshpass" || {
                                bar "apt-get install sshpass" || {
                                    error "No se pudo instalar sshpass."
                                    exit 1
                                }
                            }
                            info "Introduce la direccion IP del servidor ssh."
                            until [[ "${get_banner_ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "${get_banner_ip}" =~ (?=^.{4,253}$)(^(?:[a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,}|xn--[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$) ]];do
                                read -r -p "$(echo -e "${WHITE}[*] IP / DOMINIO : ")" get_banner_ip
                            done
                            banner_file="${user_folder}/FenixManager/banner/${get_banner_ip}"
                            timeout 5s sshpass -p "fenixmanager" ssh -o StrictHostKeyChecking=no "${get_banner_ip}" &> /tmp/banner_ssh_tmp
                            [[ $(wc -l /tmp/banner_ssh_tmp | cut -d" " -f1) -gt 1 ]] || {
                                error "No se pudo obtener el banner del servidor ssh."
                                info "El servidor no tiene un banner configurado."
                                info "O hay un problema de conexion."
                                exit 1
                            }
                            sed -i '/Permission denied, please try again./d' /tmp/banner_ssh_tmp
                            cat "/tmp/banner_ssh_tmp" > "${banner_file}"
                            rm /tmp/banner_ssh_tmp
                            change_banner "${banner_file}"
                            ;;
                        4 ) # ! INPUT BANNER
                            info "Cuando termine de introducir el banner, presiona la combinacion: ${YELLOW}CTRL + D ${WHITE}."
                            info "Puede que necesites presionar unas dos o tres veces la combinacion mencionada."
                            line_separator 62
                            local banner_array
                            readarray -t banner_array
                            line_separator 62
                            read -r -p "$(echo -e "${WHITE}[*] Nombre del archivo : ")" banner_file
                            banner_file="${user_folder}/FenixManager/banner/${banner_file// /_}"

                            echo "${banner_array[@]}" > "${banner_file}"
                            change_banner "${banner_file}"
                    esac
                }
                banner_select && {
                    info "Banner ${GREEN}${banner_file}${WHITE} cambiado correctamente."
                    sleep 4
                    cfg_ssh_dropbear
                } || {
                    error "No se pudo cambiar el banner."
                    read -r -p "$(echo -e "${WHITE}[*] Presiona enter para continuar...")"
                    cfg_ssh_dropbear
                }
                ;;
            5) #  REINICIAR DROPBEAR / OPENSSH
                [[ ${dropbear_is_installed} -eq 0 ]] && bar "service dropbear restart"
                bar "service ssh restart"
                sleep 4
                cfg_ssh_dropbear
                ;;
            6) #  VER ESTADO DE DROPBEAR
                systemctl status dropbear
                ;;
            7) # ELIMINAR PUERTOS OPENSSH
                del_openssh_port
                ;;
            "cls" | "CLS")
                cfg_ssh_dropbear
                ;;
            [bB])
                option_menu_software
                ;;
            [mM])
                fenix
                ;;
            q|Q|e|E)
                exit 0
                ;;
       esac
    done
}

cfg_badvpn(){
    clear
    echo -e "${BLUE}〢────────────────〢 ${WHITE}CONFIGURANDO BADVPN UDPGW${BLUE} 〢─────────────〢"
    local badvpn_udpgw="$(which badvpn-udpgw)"
    local cron_file="/etc/cron.d/fenixmanager"
    local guardian_is_installed=$(cat ${cron_file} | grep -c "udpgw-guardian.bash" )
    local down_port=0
    local ports_
    show_info(){
        ports_=$(cat "${cron_file}" | grep "/bin/badvpn-udpgw" | grep -Eo "127.0.0.1:[0-9]{1,5}" | cut -d: -f2 | xargs )
        local str_=""
        for i in ${ports_};do
            netstat -lntup | grep ":${i} " -q  && local str_+="${GREEN} ${i}" || {
                    local str_+="${RED} ${i}"
                    down_port=$((down_port+1))
            }
        done
        local str_badvpn color_
        
        pgrep "badvpn-udpgw" &>/dev/null && {
            str_badvpn="[ ACTIVO ]"
            color_="${GREEN}"
        } || {
            str_badvpn="[ INACTIVO ]"
            color_="${RED}"
        }
        printf "${WHITE}〢 ${WHITE}%-8s ${color_}%-10s${WHITE} %$((60-${#str_badvpn}-8))s \n" "ESTADO:" "${str_badvpn}" "〢"
        printf "${WHITE}〢 %-5s%-${#ports_}b ${WHITE} %$((60-9-${#ports_}))s \n" "PUERTOS:" "${str_}" "〢"
        line_separator 60
    }
    show_info
    option_color 1 "AGREGAR PUERTO"
    option_color 2 "ELIMINAR PUERTO"
    [[ $down_port -eq 0 ]] && option_color 3 "${RED}DETENER${WHITE} TODOS LOS PUERTOS" || option_color 3 "${GREEN}INICIAR${WHITE} TODOS LOS PUERTOS"
    [[ $guardian_is_installed -eq 0 ]] && option_color 4 "${GREEN}ACTIVAR ${WHITE}GUARDIAN${WHITE}" || option_color 4 "${RED}DESACTIVAR ${WHITE}GUARDIAN${WHITE}"
    option_color M "MENU"
    option_color E "SALIR"

    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        printf "\33[2K\r${WHITE}[$BBLUE${prompt}${WHITE}] : " 2>/dev/null && read   option
        case $option in 
            1 ) # ! AGREGAR PUERTOS
                {
                    port_input && local new_port="${puertos_array[0]}" && unset puertos_array
                    local cron_string="@reboot root screen -dmS badvpn-${new_port} ${badvpn_udpgw} --loglevel 0  --listen-addr 127.0.0.1:${new_port} --udp-mtu 1500"
                    echo -e "${cron_string}" >> "${cron_file}"
                    screen -dmS badvpn ${badvpn_udpgw} --loglevel 0  --listen-addr 127.0.0.1:${new_port} --udp-mtu 1500 && {
                        service cron restart || {
                            error "No se pudo reiniciar el servicio cron."
                            return 0
                        }
                        info "Puerto ${new_port} agregado."
                    } || {
                        error "No se pudo agregar el puerto ${new_port}."
                    }
                }
                sleep 2
                cfg_badvpn
                ;;
            2 ) # ! ELIMINAR PUERTO
                {
                    local ports_=($(cat "${cron_file}" | grep "/bin/badvpn-udpgw" | grep -Eo "127.0.0.1:[0-9]{1,5}" | cut -d: -f2 | xargs ))
                    info "Seleccione el puerto a eliminar."
                    for ((i=0;i<${#ports_[@]};i++));do
                        echo -e "\t${WHITE}[ ${BLUE}${i}${WHITE} ] ${GREEN}${ports_[$i]}${WHITE}"
                    done
                    # until port_index is lees than ${i}
                    while true;do
                        trap ctrl_c SIGINT SIGTERM
                        read -r -p "$(echo -e "${WHITE}[*] Opcion  : ")" port_index
                        if [[ ${port_index} -ge 0 && ${i} -le ${i} ]];then
                            local port_del="${ports_[$port_index]}"
                            local line_contain_port="$(cat "${cron_file}" | grep --line-number "127.0.0.1:${port_del}" | cut -d: -f1 )"
                            sed -i "${line_contain_port}d" "${cron_file}"
                            delete_empty_lines "${cron_file}"
                            service cron restart &>/dev/null && {
                                info "Puerto ${port_del} eliminado."
                            } || {
                                error "No se pudo reiniciar el servicio cron."
                            }
                            fuser ${port_del}/tcp -k &>/dev/null
                            break
                        else
                            error "Opcion invalida."
                            continue
                        fi
                    done
                }
                sleep 2
                cfg_badvpn
                ;;
            3 ) # ! DETENER / INICIAR TODOS LOS PUERTOS
                {
                    if [[ ${down_port} -eq 0 ]];then
                        killall badvpn-udpgw &>/dev/null && {
                            info "Todos los puertos fueron detenidos."
                        } || {
                            error "Fallo al detener todos los puertos."
                        }
                    else
                        for i in ${ports_};do
                            netstat -lntup | grep ":${i} " -q || {
                                # start port
                                screen -dmS "badvpn-${i}" "${badvpn_udpgw}" --loglevel 0  --listen-addr 127.0.0.1:${i} --udp-mtu 1500 && {
                                    info "Puerto ${i} iniciado."
                                } || {
                                    error "No se pudo iniciar el puerto ${i}."
                                }
                            }
                        done
                    fi
                }
                sleep 2
                cfg_badvpn
                ;;
            4 ) # ! ACTIVAR GUARDIAN
                [[ $guardian_is_installed -eq 0 ]] && {
                    info "'Guardian',es simplemente una tarean crontab que: comprobara cada 10 minutos si el servidor badvpn esta activo,si no lo esta,lo iniciara."
                    local str_cron="*/10 * * * * root /etc/FenixManager/funciones/udpgw-guardian.bash 1"
                    echo -e "${str_cron}" >> "${cron_file}"
                    service cron restart &>/dev/null
                    read -r -p "$(echo -e "${WHITE}[*] Presione enter para continuar...")"
                } || {
                    local line_number_guardian="$(cat "${cron_file}" | grep --line-number "/etc/FenixManager/funciones/udpgw-guardian.bash" | cut -d: -f1 )"
                    sed -i "${line_number_guardian}d" "${cron_file}"
                    delete_empty_lines "${cron_file}"
                    service cron restart &>/dev/null
                }
                cfg_badvpn
                ;;
            [mM]) fenix ;;
            [eEqQ]) exit 0 ;;
            *) tput cuu1 && tput el1
        esac
    done
}


del_openssh_port(){
    local ssh_ports=($(grep "^Port" ${ssh_file} | cut -d' ' -f2 | tr "\n" ' '))
    for ((i=0;i<${#ssh_ports[@]};i++));do
        local port=${ssh_ports[$i]}
        [[ ${port} -eq 22 ]] && {
            echo -e "\t${WHITE}[ ${BLUE}!${WHITE} ] ${GREEN}${port}${WHITE} (${RED}Este puerto no se puede eliminar.${WHITE})"
            } || {
                echo -e "\t${WHITE}[ ${BLUE}${i}${WHITE} ] ${GREEN}${port}${WHITE}"
            }
    done
    if [[ ${#ssh_ports[@]} -eq 1 ]];then
        info "No hay puertos SSH disponibles para eliminar."
        return 0
    fi
    while true;do
        trap ctrl_c SIGINT SIGTERM
        read -r -p "$(echo -e "${WHITE}[*] Opcion  : ")" port_index
        if [[ ${port_index} -ge 0 && ${port_index} -lt ${#ssh_ports[@]} ]];then
            local port_to_del=${ssh_ports[$port_index]}
            [[ ${port_to_del} -eq 22 ]] && {
                error "El puerto ( ${port_to_del} ) no se puede eliminar."
                continue
            } || {
                sed -i "/^Port ${port_to_del}$/d" ${ssh_file}
                bar "service ssh restart"
                info "Puerto ${port_to_del} eliminado."
                return 0
            }
        else
            error "Opcion invalida."
            continue
        fi
    done
}


pysocks_del_port() {
    local port_to_delete
    if [[ -z ${@} ]];then
        local ports_list=$(grep "accept" ${config_file} | cut -d "=" -f 2 | cut -d ":" -f 2 | cut -d "]" -f 1 | sort -u)
        local ports_list_array=(${ports_list})
        local number_of_ports=${#ports_list_array[@]}
        if [[ $number_of_ports -eq 0 ]];then error "No hay puertos configurados." ; fi
            info "Seleccione el puerto a eliminar :"
        for (( i=0; i<${number_of_ports}; i++ ));do
            echo -e "\t${WHITE}[ ${i} ] ${GREEN}${ports_list_array[$i]}${WHITE}"
        done
        while true;do
            trap ctrl_c SIGINT SIGTERM
            read -p "$(echo -e "${BLUE}[*] opcion  : ${END_COLOR}")" port_to_delete
            if [[ $port_to_delete =~ ^[0-9]+$ ]];then
                if [[ $port_to_delete -ge 0 && $port_to_delete -le ${number_of_ports} ]];then break ; fi
            else
                error "Opcion invalida."
                continue
            fi
        done
    fi
    [[ -n "${1}" ]] && port_to_delete=${1} || port_to_delete="${ports_list_array[$port_to_delete]}"
    local line_of_port=$(grep "accept=${port_to_delete}" --line-number ${config_file} | cut -d: -f1 | head -1) 
    local line_of_port=$((line_of_port-1))
    local array_lines_delete
    for (( i=$line_of_port; i<$((line_of_port+5)); i++ ));do array_lines_delete+="${i}d;" ; done
    sed -i "${array_lines_delete}" ${config_file}
    fuser  ${port_to_delete}/tcp -k &>/dev/null
    sed '/^[[:space:]]*$/d' -i ${config_file} 
    systemctl restart fenixmanager-pysocks &>/dev/null
}



