#!/usr/bin/bash

source "/etc/FenixManager/preferences.bash"
source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/color.bash"
source "/etc/FenixManager/funciones/ovpn.bash"
source "/etc/FenixManager/funciones/cfg-pkt.bash"

script_executed_with_root_privileges



squid_proxy_install () {
    trap "exit 130" SIGINT SIGTERM
    clear
    separator "INSTALANDO SQUID-PROXY"
    bar 'apt-get install squid -y'
    if [[ $? != 0 ]];then
        error "Error al instalar Squid-Proxy"
        exit $?
    fi
    
    get_all_ip_from_adapters
    rm /etc/squid/ip_allow &> /dev/null
    rm /etc/squid/domain_allow &> /dev/null && touch /etc/squid/domain_allow
    for i in "${IPS_LISTS[@]}";do echo "$i" >> "/etc/squid/ip_allows" ; done
    
    while true;do
        trap ctrl_c SIGINT SIGTERM SIGKILL
        read -p "$(echo -e "$YELLOW[*] Ingrese el puerto de escucha (separados por espacio):${endcolor}") " squid_port
        
        if [[ -z $squid_port ]] ;then error 'El puerto ingresado esta vacio.' ; continue ; fi

        
        IFS=' ' read -r -a squid_port <<< "$squid_port"
        squid_port_array=()
        for i in "${squid_port[@]}";do
            if [[ ! $(grep -E '^[0-9]+$' <<< $i) ]] ;then error "El puerto ($i) no es un numero" ; continue ; fi
            if [ $i -lt 1 ] || [ $i -gt 65535 ] ;then error 'El puerto ingresado no es valido.' ; continue ; fi
            if check_if_port_is_open $i ;then
                squid_port_array+=($i)
                ufw allow $i/tcp &> /dev/null
            else
                error "Omitiendo el puerto ($i), no esta disponible."
            fi
        done
        break
    done
    config_file='/etc/squid/squid.conf'
    cp $config_file $config_file'.bak'
    
    cfg="http_port $squid_port_array\nacl whitelist dst '/etc/squid/ip_allow'\nacl domain_whitelist dstdomain '/etc/squid/domain_allow'\nhttp_access allow whitelist\nhttp_access allow domain_whitelist\nhttp_access deny all\n"
    echo -e $cfg > "/etc/squid/squid.conf"
    bar "systemctl restart squid"
    
    if [[ $? != 0 ]];then
        error 'No se pudo reiniciar/instalar squid'
        exit 1
    else
        info 'Squid instalado y configurado correctamente.'
    fi

    read -p "$(echo -e "$YELLOW[*] Presione enter para continuar.${endcolor}") " option
}

install_stunnel4() {

    clear
    # check if stunnel is installed
    separator "INSTALANDO STUNNEL"  
    bar 'apt-get install stunnel4 -y'
    if [[ $? != 0 ]];then  error 'No se pudo instalar stunnel4' ; exit $? ; fi

    stunnel4_whats_cert_to_use
    
    ssl_port=()
    # stunnel listen port
    until [[ $ssl_port =~ ^[0-9]+$ ]] && [[ $ssl_port -ge 1 ]] && [[ $ssl_port -le 65535 ]];do
        trap ctrl_c SIGINT SIGTERM SIGKILL
        read -p "$(echo -e "$BLUE[*] Ingrese el puerto para stunnel4 ${endcolor}") : " ssl_port
        if [[ -z $ssl_port ]] ;then error 'El puerto ingresado esta vacio.'; continue ; fi
        
        IFS=' ' read -r -a ssl_port <<< "$ssl_port"
        ssl_port_array=()
        for i in "${ssl_port[@]}";do
            if [[ ! $(grep -E '^[0-9]+$' <<< $i) ]] ;then error "El puerto ($i) no es un numero" ; continue ; fi
            if [[ $i -lt 1 ]] || [[ $i -gt 65535 ]] ;then error 'El puerto ingresado no es valido.' ; continue ; fi
            check_if_port_is_open $i
            
            if [[ $? != 1 ]];then
                ssl_port_array+=($i)
                ufw allow $i &> /dev/null

            else
                error "Omitiendo el puerto ($i), no esta disponible."
            fi
        done
    done
    # service port
    while true;do
        redirect_to_service
        break
        done
    local service_port=$SERVICE_REDIRECT
    
    local cfg="output  = /var/log/stunnel4/stunnel.log\nclient = no\n"
    if [[  $CERT_FILE =~ ".pem" ]];then
        cfg+="cert = $CERT_FILE\n"
    else
        cfg+="cert = $CERT_FILE\n"
        cfg+="key = $KEY_FILE\n"
    fi
    local sshd_cfg="\n[custom#1]\naccept = $ssl_port_array\nconnect = $service_port\n"
    
    echo -e $cfg > "/etc/stunnel/stunnel.conf"
    echo -e $sshd_cfg >> "/etc/stunnel/stunnel.conf"
    bar 'service stunnel4 restart'
    if [[ $? != 0 ]];then
        error 'No se pudo reiniciar/configurar stunnel4'
        exit 1
    else
        info 'Stunnel4 instalado y configurado correctamente.'
    fi
    read -p "$(echo -e "$YELLOW[*] Presione enter para continuar.${endcolor}") " option
    fenix
}

install_slowdns() {
    trap ctrl_c SIGINT SIGTERM SIGKILL
    clear
    separator "INSTALANDO SLOWDNS"
    chmod +x $script_dir/bin/slowdns
    local key=$(mktemp)
    local pub=$(mktemp slowdns_pub.XXX)
    local regex_domain='(?=^.{4,253}$)(^(?:[a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,}|xn--[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$)'

    while [[ -z "$domain" ]] ; do
        trap ctrl_c SIGINT SIGTERM SIGKILL
        read -p "$(echo -e "$YELLOW[*] Ingrese el NS (NameServer) de su dominio : ${endcolor}")" domain
        if [[ -z $domain ]];then continue ; fi
        grep -P $regex_domain <<< $domain &>/dev/null
        if [[ $? == 0 ]];then break ; fi
        break
    done

    $script_dir/bin/slowdns -gen-key -privkey-file "$key" -pubkey-file "$pub" 1>/dev/null 
    info "Clave publica : $(cat $pub)"
    echo -e "$(cat $pub)" > "${user_folder}/FenixManager/slowdns_pubkey"
    info "Se recomienda seleccionar la opcion correspondiente a SSH/DROPBEAR"
    local local_service=22
    iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353
    
    $script_dir/bin/slowdns -udp :5353 -privkey-file $key $domain 127.0.0.1:$local_service &>/dev/null &
    
    if [[ $? == 0 ]];then
        info 'slowdns iniciado correctamente.'
    else
        error 'Error al iniciar slowdns.'
    fi
    read -p "$(echo -e "$YELLOW[*] Presione enter para continuar.${endcolor}") " option

}

install_shadowsocks() {
    clear
    separator "INSTALANDO SHADOWSOCKS"
    trap ctrl_c SIGINT SIGTERM SIGKILL
    bar "apt-get install shadowsocks-libev --install-suggests -y" && systemctl stop shadowsocks-libev.service
    if [[ $? != 0 ]];then
        error 'No se pudo instalar shadowsocks-libev'
        exit $?
    fi
    
    # puerto
    while true;do
        trap ctrl_c SIGINT SIGTERM SIGKILL
        read -p "$(echo -e "$WHITE[*] Ingrese el puerto para shadowsocks (8388): ${WHITE}")" port
        port=${port:-8388}
        grep -E '^[0-9]+$' <<< $port &>/dev/null
        if [[ $? != 0 ]];then error 'El puerto ingresado no es valido.' ; continue ; fi
        if [[ $port -lt 1 ]] || [[ $port -gt 65535 ]] ;then error 'El puerto ingresado no es valido.' ; continue ; fi
        check_if_port_is_open $port
        if [[ $? -eq 0 ]];then
                ufw allow $port/tcp &> /dev/null
                break
        else
            error "El puerto ($port), no esta disponible."
            continue
        fi
        
        break
    done
    
    while true;do
        trap ctrl_c SIGINT SIGTERM SIGKILL
        random_passwd=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12 ; echo '')
        read -p "$(echo -e "$YELLOW[*] Ingrese el password para shadowsocks (random password): ${WHITE}")" passwd
        if [[ -z $passwd ]] ;then info "Se genero una contraseña random: ${RED}$random_passwd" ; passwd=$random_passwd ;break ;fi
        break
    done

    local tmp_file=$(mktemp)
    jq -n --argjson port $port --arg passwd "$passwd"  '{"server":["0.0.0.0"],"mode":"tcp_and_udp","server_port":$port,"local_port":1080,"password":$passwd,"timeout":60,"method":"chacha20-ietf-poly1305"}' &> $tmp_file
    mv $tmp_file /etc/shadowsocks-libev/config.json && chmod 644 /etc/shadowsocks-libev/config.json
    update_config_uri
    bar "systemctl enable shadowsocks-libev.service"
    info 'ShadowSocks configurado correctamente.'
    info "Shadowsocks uri: ${GREEN}$uri_shadowsocks${WHITE}"
    setup_fail2ban(){
        info "Agregando reglas para fail2ban"
        local filer_cfg="W0lOQ0xVREVTXQpiZWZvcmUgPSBjb21tb24uY29uZgpbRGVmaW5pdGlvbl0KX2RhZW1vbiA9IHNzLXNlcnZlcgpmYWlscmVnZXggPSBeXHcrXHMrXGQrIFxkKzpcZCs6XGQrXHMrJShfX3ByZWZpeF9saW5lKXNFUlJPUjpccytmYWlsZWQgdG8gaGFuZHNoYWtlIHdpdGggPEhPU1Q+OiBhdXRoZW50aWNhdGlvbiBlcnJvciQKaWdub3JlcmVnZXggPSAKZGF0ZXBhdHRlcm4gPSAlJVktJSVtLSUlZCAlJUg6JSVNOiUlUwo="
        echo -e "$filer_cfg" | base64 -d > /etc/fail2ban/filter.d/shadowsocks-libev.conf
        local jail_cfg="I3NoYWRvd3NvY2tzLWxpYmV2LWluaXQtY29uZmlnCltzaGFkb3dzb2Nrcy1saWJldl0KZW5hYmxlZCA9IHRydWUKZmlsdGVyID0gc2hhZG93c29ja3MtbGliZXYKcG9ydCA9IDg4MzkKbG9ncGF0aCA9IC92YXIvbG9nL3N5c2xvZwoKbWF4cmV0cnkgPSAzCmZpbmR0aW1lID0gMzYwMApiYW50aW1lID0gMzYwMAojc2hhZG93c29ja3MtbGliZXYtZW5kLWNvbmZpZwo="
        echo -e "$jail_cfg" | base64 -d >> /etc/fail2ban/jail.conf 
        bar "systemctl restart fail2ban"
        if [[ $? == 0 ]];then
            info 'Fail2ban configurado correctamente.'
        else
            error 'Error al configurar fail2ban.'
        fi
    }
    setup_fail2ban


    read

}

install_python3_proxy(){
    trap ctrl_c SIGINT SIGTERM SIGKILL
    clear
    separator "INSTALANDO PYTHON3-PROXY"
    
    # Bueno, ahora no lo hago. Pero despues tendre que verificar si esta instalado: python3 pip3 y los modulos necesarios.
    info "Agregado un servicio a systemd."
    sed -i "s|user_dir_replace_with_sed|${user_folder}/|g" "${script_dir}/funciones/py-proxy/main_service.py"
    cp "${script_dir}/funciones/py-proxy/fenixmanager-pysocks.service" /etc/systemd/system/fenixmanager-pysocks.service
    bar "systemctl daemon-reload"
    bar "systemctl enable fenixmanager-pysocks.service"
    info "Creando directorio de configuracion."
    mkdir -p "${user_folder}/FenixManager/config" &>/dev/null
    bar "systemctl enable fenixmanager-pysocks.service"
    info "Servicio agregado correctamente."
    sleep 3
    cfg_python3_proxy
    
}