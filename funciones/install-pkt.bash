#!/bin/bash

source "/etc/FenixManager/preferences.bash" 2>/dev/null
source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/color.bash" 2>/dev/null
source "/etc/FenixManager/funciones/ovpn.bash"
source "/etc/FenixManager/funciones/cfg-pkt.bash"

script_executed_with_root_privileges

squid_proxy_install () {
    trap "exit 130" SIGINT SIGTERM
    clear
    echo -e  "${BLUE}〢─────────────〢${WHITE} CONFIGURANDO SQUID-PROXY ${BLUE}〢─────────────────〢${WHITE}"
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

    read -p "$(echo -e "$YELLOW[*] Presione enter para continuar.${endcolor}") "
    clear
    fenix
}

install_stunnel4() {
    clear
    echo -e "${BLUE}〢──────────────────〢 ${WHITE}INSTALANDO STUNNEL4${BLUE} 〢─────────────────〢"
 
    bar 'apt-get install stunnel4 -y'
    if [[ $? != 0 ]];then  error 'No se pudo instalar stunnel4' ; exit $? ; fi

    stunnel4_whats_cert_to_use
    
    ssl_port=()
    
    port_input && {
        local ssl_port=${puertos_array[0]}
        unset puertos_array
    }
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
    local sshd_cfg="\n[custom#1]\naccept = ${ssl_port}\nconnect = ${service_port}\n"
    
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
    echo -e "${BLUE}〢───────────────────〢${WHITE} INSTALANDO SLOWDNS ${BLUE}〢─────────────────〢${WHITE}"
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
    local local_service=22
    iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353
    
    $script_dir/bin/slowdns -udp :5353 -privkey-file $key $domain 127.0.0.1:$local_service &>/dev/null &
    
    if [[ $? == 0 ]];then
        info 'slowdns iniciado correctamente.'
    else
        error 'Error al iniciar slowdns.'
    fi
    rm "${pub}" &>/dev/null
    read -p "$(echo -e "$YELLOW[*] Presione enter para continuar.${endcolor}") " option
    cfg_slowdns

}

install_shadowsocks() {
    clear
    echo -e "${BLUE}〢─────────────────〢 ${WHITE}INSTALANDO SHADOWSOCKS ${BLUE}〢───────────────〢"
    trap ctrl_c SIGINT SIGTERM SIGKILL
    bar --cmd "apt-get install shadowsocks-libev --install-suggests -y" --title "Instalando shadowsocks-libev" && systemctl stop shadowsocks-libev.service
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
    bar "systemctl enable shadowsocks-libev.service"
    info 'ShadowSocks configurado correctamente.'
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
    cfg_shadowsocks

}

install_python3_proxy(){
    trap ctrl_c SIGINT SIGTERM SIGKILL
    clear
    echo -e "${BLUE}〢────────────〢 ${WHITE}INSTALANDO FENIXMANAGER-PYSOCKS ${BLUE}〢───────────〢"
    info "Agregado un servicio a systemd."
    sed -i "s|user_dir_replace_with_sed|${user_folder}/|g" "${script_dir}/funciones/py-proxy/main_service.py"
    cp "${script_dir}/funciones/py-proxy/fenixmanager-pysocks.service" /etc/systemd/system/fenixmanager-pysocks.service

    bar "systemctl daemon-reload"
    bar "systemctl enable fenixmanager-pysocks.service"
    bar "systemctl enable fenixmanager-pysocks.service"
    info "Servicio agregado correctamente."
    sleep 3

    cfg_python3_proxy
}
install_badvpn_udpgw(){
    local fenixmanager_crontab="/etc/cron.d/fenixmanager"
    info "Descargando badvpn-udpgw"
    rm -rf /tmp/badvpn &>/dev/null
    git clone https://github.com/ambrop72/badvpn /tmp/badvpn &> /dev/null
    cd "/tmp/badvpn" 
    mkdir "build" && cd "build"
    info "Construyendo badvpn-udpgw"
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 -DCMAKE_INSTALL_PREFIX=/ &> /dev/null && {
        info "Instalando..."
        make install
        info "Por defecto,updgw escuchara en la direccion ${YELLOW}127.0.0.1:7300${WHITE} ."
        local badvpn_udpgw=$(which badvpn-udpgw 2>/dev/null)
        echo -e "\n@reboot root screen -dmS badvpn ${badvpn_udpgw} --loglevel 0  --listen-addr 127.0.0.1:7300 --udp-mtu 1500" >> "${fenixmanager_crontab}"
        screen -dmS badvpn ${badvpn_udpgw} --listen-addr 127.0.0.1:7300
    } || {
        rm "/tmp/badvpn" -rf &>/dev/null
        error "No se pudo compilar el repositorio ${badvpn_git}."
        read
        }
}

install_fenixssh(){
    local arch=$(uname -m)
    local rsa="${user_folder}/.ssh/id_rsa"
    local binaries="${script_dir}/funciones/fenixssh/fenixssh-${arch}"
    local port=0
    
    if [ "$arch" != "x86_64" ] && [ "$arch" != "aarch64" ]; then
        error "Arquitectura de cpu no sportadar."
        info "Contacta con el administrador para darle soporte."
        info "Telegram: @Mathiue1001"
    fi
    if [ ! -f "$binaries" ];then
        error "No se encontro el binario de FenixSSH."
        exit 1
    fi
    
    touch /var/log/FenixManager/connFenixssh.json &>/dev/null

    while true ;do
        read -p "$(echo -e "$YELLOW[*] Ingrese el puerto de escucha ( Recomendado: 2222 ):${endcolor}") " port
        check_if_port_is_open $port
        if [[ $? -eq 0 ]];then ufw allow $port  &>/dev/null; break ; else continue ; fi
    done
    if [ ! -f "$rsa" ];then
        error "No se encontro una clave ssh privada."
        info "Genere una con ssh-keygen -t rsa ."
        exit 1
    fi
    info "El banner 'fenixssh.html' fue diseñado para ser utilizado con fenixssh."
    local fenixssh_banner="<font color=#0000FF>〢 ──────────────────────── 〢</font><br><b><font color=#FFFFFF>〢 Script: </font><font color=#FF0000>FenixManager</font><font color=#FFFFFF> 〢</font></b><br><font color=#FFFFFF>〢 Usuario: </font><font color=#FF0000>[user]</font><font color=#FFFFFF> 〢</font><br><font color=#FFFFFF>〢 Expira: </font><font color=#FF00FF>[exp]</font><font color=#FFFFFF> 〢</font><br><font color=#FFFFFF>〢 Máxima conexiones: </font><font color=#FF0000>[maxConn]</font><font color=#FFFFFF> 〢</font><br><font color=#0000FF>〢 ──────────────────────── 〢</font><br>"
   
    echo "${fenixssh_banner}" > "${user_folder}/FenixManager/banner/fenixssh.html"
    list_banners
    
    cp "$binaries" "/usr/bin/fenixssh" &>/dev/null
    chmod 777 "/usr/bin/fenixssh"&>/dev/null

    rm "${user_folder}/FenixManager/config/fenixssh.json" &>/dev/null
    
    echo '{}' | jq --arg bind_port "$port" \
   --arg banner "$BANNER_FILE" \
   --arg ssh_key "$rsa" \
   '.bind_port = $bind_port | .banner = $banner | .ssh_key = $ssh_key' > temp.json && mv temp.json "${user_folder}/FenixManager/fenixssh.json"

    cp "${script_dir}/funciones/fenixssh/fenixmanager-fenixssh.service" /etc/systemd/system/fenixmanager-fenixssh.service

    bar "systemctl daemon-reload"
    bar "systemctl enable fenixmanager-fenixssh.service"
    bar "systemctl enable fenixmanager-fenixssh.service"
    bar "systemctl start fenixmanager-fenixssh.service"
    info "Servicio agregado correctamente."
    
    sleep 3
    cfg_fenixssh
}

install_udpcustom(){
    local bin="${script_dir}/bin/udpcustom/udp-custom"
    local config="${script_dir}/bin/udpcustom/config.json"
    
    rm -rf /root/udp    &> /dev/null
    mkdir -p /root/udp  &> /dev/null
    info "Se recomienda excluir el puerto de badvpn-udpgw. Por defecto es el 7300, o los de otros servicios: zivpn-udp."
    read -p "$(echo -e "$YELLOW[*] Ingrese los puertos a excluir ( separados por , (coma) ):${endcolor}") " exclude_port
    cp "$bin" /root/udp/          &> /dev/null   
    cp "$config" /root/udp/          &> /dev/null   
    chmod +x /root/udp/udp-custom &> /dev/null
    info "Creando servicio systemd"
    if [ -z "$exclude_port" ]; then
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Tea
[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server -c config.json
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2
[Install]
WantedBy=default.target
EOF
else
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Tea
[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server -exclude $exclude_port -c config.json
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2
[Install]
WantedBy=default.target
EOF
fi
    bar --title "systemctl start udp-custom" --cmd "systemctl start udp-custom" || {
        rm "/etc/systemd/system/udp-custom.service" &>/dev/null
        rm -rf /root/udp    &> /dev/null
        error "Fallo al ininiar udp-custom"
        exit 1 
    } && {
        bar --title "systemctl enable udp-custom" --cmd "systemctl enable udp-custom"
        bar --cmd "ufw disable"
    }
    info "Presione enter para reiniciar su vps"
    read
    reboot
}

install_udpzivpn(){
    local arch=$(uname -m)
    local url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-"
    local iface=$(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1)
    if [[ $arch == "x86_64" ]]; then
        url+="amd64"
    else
        url+="arm64"
    fi

    systemctl stop zivpn.service &>/dev/null 
    bar --title "Descargando zivpn-udp" --cmd "wget ${url} -O /usr/local/bin/zivpn"
    chmod +x /usr/local/bin/zivpn
    mkdir /etc/zivpn &>/dev/null
    bar --title "Descargando archivo de configuracion" --cmd "wget https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json"

    info  "Generando certificados:"
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt"
    sysctl -w net.core.rmem_max=16777216 &>/dev/null
    sysctl -w net.core.wmem_max=16777216 &>/dev/null

    cat <<EOF > /etc/systemd/system/zivpn.service
    [Unit]
    Description=zivpn VPN Server
    After=network.target

    [Service]
    Type=simple
    User=root
    WorkingDirectory=/etc/zivpn
    ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
    Restart=always
    RestartSec=3
    Environment=ZIVPN_LOG_LEVEL=info
    CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
    AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
    NoNewPrivileges=true

    [Install]
    WantedBy=multi-user.target
EOF

    info "Creando la tabla '${YELLOW}zivpn${WHITE}' dentro de la base de datos '${YELLOW}usuarios${WHITE}'"
    sqlite3 "/etc/FenixManager/database/usuarios.db"  'CREATE TABLE zivpn (password VARCHAR(32) NOT NULL,exp_date DATETIME);' || {
        error "Fallo al crear la tabla."
    }
    info "Esa contraseña no tendra fecha de expiracion. Las que agreges despues si."
    read -p "$(echo -e "$YELLOW[*] Ingrese una contraseña. ( Default: fenix ):${endcolor}") " input_config
    info "Despues podras agregar mas, desde el respectivo menu de configuracion"
    if [ -z "$input_config" ];then
        input_config="fenix"
    fi
    
    jq  --arg passwd  "${input_config}" '.auth.config = [$passwd]' /etc/zivpn/config.json > tmp.json && mv tmp.json /etc/zivpn/config.json 

    bar "systemctl enable zivpn.service"
    bar "systemctl start zivpn.service"
    iptables -t nat -A PREROUTING -i ${iface} -p udp --dport 6000:19999 -j DNAT --to-destination :5667 ||  {
        error "Fallo al agregar la regla iptable."
        info "Puedes probar agregandola manualmente."
        info "iptables -t nat -A PREROUTING -i ${iface} -p udp --dport 6000:19999 -j DNAT --to-destination :5667"
    }
    ufw allow 6000:19999/udp &>/dev/null
    ufw allow 5667/udp        &>/dev/null
    rm zi.* 1> /dev/null 2> /dev/null
    info "Despues de reciniciar tendras que agregar las reglas iptables, para su correcto funcionamiento. Esto se pude hacer desde su respectivo menu de configuracion."
    info "ZIVPN UDP instalado"
    cfg_udpzivpn
}
