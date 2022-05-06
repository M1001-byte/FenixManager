#!/usr/bin/bash

# Este script,es una copia del siguiente repositorio: https://github.com/angristan/openvpn-install
# Yo,simplemente lo he modificado para adaptarlo para FenixManager.(Ademas de pequeños cambios/traducciones)

db_ovpn='/etc/FenixManager/database/usuarios.db'


source "/etc/FenixManager/preferences.bash"
source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/color.bash"

script_executed_with_root_privileges

trap ctrl_c SIGINT SIGTERM

create_db_user_ovpn() {
    trap ctrl_c SIGINT SIGTERM
    mkdir -p /etc/FenixManager/database &>/dev/null
    # check if database exists
    table_exist=$(sqlite3 $db_ovpn "SELECT name FROM sqlite_master WHERE type='table' AND name='ovpn'" | grep 'ovpn' -c)
    if [[ ! $table_exist -eq 0 ]];then
        return 0
    else
        info "Creando la tabla 'ovpn' en la base de datos."
        sqlite3 $db_ovpn 'CREATE TABLE ovpn (nombre VARCHAR(32) NOT NULL, exp_date DATETIME);'
        if [[ $? -eq 0 ]];then
            info "La tabla 'ovpn' se ha creado correctamente."
            sleep 2
            main
        else
            error "Error al crear la tabla 'ovpn'."
            exit 1
        fi
    fi

}

installUnbound() {
    trap ctrl_c SIGINT SIGTERM
    if [[ ! -e /etc/unbound/unbound.conf ]];then
        bar "apt-get install unbound -y"

        echo -e 'interface: 10.8.0.1\naccess-control: 10.8.0.1/24 allow\nhide-identity: yes\nhide-version: yes\nuse-caps-for-id: yes\nprefetch: yes' >>/etc/unbound/unbound.conf
    else # Si ya existe un archivo de configuracion de unbound
        echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf
        echo -e 'c2VydmVyOgppbnRlcmZhY2U6IDEwLjguMC4xCmFjY2Vzcy1jb250cm9sOiAxMC44LjAuMS8yNCBhbGxvdwpoaWRlLWlkZW50aXR5OiB5ZXMKaGlkZS12ZXJzaW9uOiB5ZXMKdXNlLWNhcHMtZm9yLWlkOiB5ZXMKcHJlZmV0Y2g6IHllcwpwcml2YXRlLWFkZHJlc3M6IDEwLjAuMC4wLzgKcHJpdmF0ZS1hZGRyZXNzOiBmZDQyOjQyOjQyOjQyOjovMTEyCnByaXZhdGUtYWRkcmVzczogMTcyLjE2LjAuMC8xMgpwcml2YXRlLWFkZHJlc3M6IDE5Mi4xNjguMC4wLzE2CnByaXZhdGUtYWRkcmVzczogMTY5LjI1NC4wLjAvMTYKcHJpdmF0ZS1hZGRyZXNzOiBmZDAwOjovOApwcml2YXRlLWFkZHJlc3M6IGZlODA6Oi8xMApwcml2YXRlLWFkZHJlc3M6IDEyNy4wLjAuMC84CnByaXZhdGUtYWRkcmVzczogOjpmZmZmOjA6MC85Ng==' | base64 -d >/etc/unbound/openvpn.conf
    fi
    bar "systemctl enable unbound"
    bar "systemctl restart unbound"
}
installQuestions() {
    create_db_user_ovpn
    trap ctrl_c SIGINT SIGTERM
    info "Bienvenido al instalador de OpenVPN."
    info "Repositorio git disponible en : $red https://github.com/angristan/openvpn-install $white"
    info "Puede dejar las opciones predeterminadas y simplemente presionar enter si está de acuerdo con ellas."
    echo ""

    # Detect public IPv4 address and pre-fill for the user
    IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

    if [[ -z "$IP" ]];then
        IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
        exit 1
    fi

    APPROVE_IP={APPROVE_IP:-n}

    if [[ "$APPROVE_IP" == n ]];then
        read -rp "IP address: " -e -i "$IP" IP
    fi

    if grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)' <<< $IP ;then
        info "Parece que este servidor está detrás de una red NAT. ¿Cuál es su dirección IPv4 pública o nombre de host?"
        PUBLICIP=$(curl -s http://ipinfo.io/ip)
        read -rp "[*] Direccion ip publica o nombre de host: " -e -i "$PUBLICIP" PUBLICIP
    fi

    info "En que puerto desea que escuche Openvpn ?"

    echo -e " ${green} [ 1 ] $white Default: 1194"
    echo -e " ${green} [ 2 ] $white Custom"
    read -rp '[*] Opcion [1-2]: ' -e -i "1" PORT_CHOICE
    
    while [[ "$PORT_CHOICE" != 1 ]] && [[ "$PORT_CHOICE" != 2 ]];do
        read -rp "'[*] Opcion [1-2]: '" -e -i "1" PORT_CHOICE
        
    done
    case $PORT_CHOICE in
        1 )
            PORT=1194
            ;;
        2 )

            # validate port
            while true;do
                read -g PORT --prompt="echo -e '[*] Puerto personalizado [1-65535]: '"
                if [[ -z "$PORT" || ! "$PORT" =~ '^[0-9]+$' ]];then
                    continue
                fi
                if [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]];then
                    error "El puerto debe estar entre 1 y 65535"
                fi
                check_if_port_is_open "$PORT"
                if [[ ! $status -eq 0 ]];then
                    continue
                fi
                break
            done
            ;;
    esac

    echo ""
    info "Que protocolo desea utilizar ?"
    info "UDP es rapido,pero obsoleto. TCP es seguro,ademas admite peticiones http (Paylaod)"
    echo -e " $green [ 1 ] $white UDP"
    echo -e " $green [ 2 ] $white TCP"
    read -rp '[*] Protocolo [1-2]: ' -e -i "1" PROTOCOL_CHOICE
    
    case $PROTOCOL_CHOICE in
        1 )
            PROTOCOL="udp"
            ;;
        2 )
            PROTOCOL="tcp"
            ;;
    esac

    info "Que servidor dns utilizara su vpn?"
    echo -e " $green [ 1 ] $blue Usar las del sistema$white (/etc/resolv.conf)"
    echo -e " $green [ 2 ] $blue Self-hosted DNS Resolver$white (Unbound)"
    echo -e " $green [ 3 ] $blue Cloudflare$white"
    echo -e " $green [ 4 ] $blue OpenDNS$white"
    echo -e " $green [ 5 ] $blue Google$white"
    echo -e " $green [ 6 ] $blue AdGuard DNS$white"
    echo -e " $green [ 7 ] $blue Custom$white"

    while true;do

        read -rp '[*] DNS [1-7]: ' -e -i "3" DNS
        if [[ -z "$DNS" ]] ;then continue ;fi
        if [[ $DNS -eq 2 ]] && [[ -e /etc/unbound/unbound.conf ]];then
            echo ""
            info "Unbound ya se encuentra instalado"
            info "Puede permitir que el script lo configure para usarlo desde sus clientes OpenVPN"
            echo "Simplemente agregaremos un segundo servidor a /etc/unbound/unbound.conf para la subred OpenVPN."
            echo ""

            while true;do
                read -l CONITNUE --prompt="[*] Aplicar cambios de configuracion a Unbound? [y/n]: '"
                if [[ "$CONITNUE" == "n" ]];then
                    DNS=''
                    CONTINUE=''
                fi
                if [[ "$CONITNUE" = 'y' ]];then
                    break
                fi
            done
        fi
        if [[ $DNS -eq 7 ]];then
            while true;do
                read -g DNS1 --prompt="echo -e '[*] DNS Primario : '"
                if [[ -z "$DNS1" ]];then continue ;fi
                if [[ ! $DNS1 =~ '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' ]];then continue ; fi

                read -g DNS2 --prompt="echo -e '[*] DNS Secundario : '"
                if [[ -z "$DNS2" ]] ; then break ; fi
                if [[ ! $DNS2 =~ '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' ]];then
                    continue
                fi
                break
            done
            
        fi
        break
    done
    echo ""
    CIPHER='AES-128-GCM'
    CERT_TYPE="1" # ECDSA
    CERT_CURVE='prime256v1'
    CC_CIPHER='TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256'
    DH_TYPE='1' # ECDH
    DH_CURVE='prime256v1'
    HMAC_ALG="SHA256"
    TLS_SIG='1' # tls-crypt

    APPROVE_INSTALL={APPROVE_INSTALL:-n}
    read -rp '[*] Presione cualquier tecla para continuar o Ctrl-C para cancelar...'
}


install_openvpn() {
    clear
    separator "INSTALANDO OPENVPN"
    trap ctrl_c SIGINT SIGTERM
    bar "apt-get install openvpn -y"
    if [[ $? != 0 ]];then
        error "Fallo al instalar openvpn."
        exit $?
    fi
    installQuestions

    # Get the "public" interface from the default route
    NIC=$(ip route | awk '/default/ { print $5 }')
    if [[ -z "$NIC" ]];then
        error "No se pudo determinar la interfaz de red"
        exit 1
    fi

    if [[ !  -f /etc/openvpn/server.conf ]];then
        bar "apt-get -y install ca-certificates gnupg"
        if [[ -d /etc/openvpn/easy-rsa/ ]];then
            rm -rf /etc/openvpn/easy-rsa/
        fi
    fi

    if (grep -qs "^nogroup:" /etc/group) ;then
        NOGROUP=nogroup
    else
        NOGROUP=nobody
    fi

    # install the lastest version for easy,if not already installed
    if [[ ! -d /etc/openvpn/easy-rsa/ ]];then
        wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz -O /tmp/EasyRSA-3.0.8.tgz &>/dev/null
        mkdir -p /etc/openvpn/easy-rsa &>/dev/null
        tar xzf /tmp/EasyRSA-3.0.8.tgz --strip-components=1 --directory /etc/openvpn/easy-rsa
        rm -f /tmp/EasyRSA-3.0.8.tgz &>/dev/null

        cd /etc/openvpn/easy-rsa/ || return
        case $CERT_TYPE in
            1)
                echo "set_var EASYRSA_ALGO ec" >vars
                echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
                ;;

            2)
                echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
                ;;

        esac

        #generate random cdn
        SERVER_CN="cn_"$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
        echo "$SERVER_CN" >SERVER_CN_GENERATED
        SERVER_NAME="server_"$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
        echo "$SERVER_NAME" >SERVER_NAME_GENERATED

        echo "set_var EASYRSA_REQ_CN $SERVER_CN" >>vars

        # Create the PKI, set up the CA, the DH params and the server certificate
        ./easyrsa init-pki &>/dev/null
        ./easyrsa --batch build-ca nopass &>/dev/null

        if [[ "$DH_TYPE" == "2" ]];then
            # ECDH keys are generated on-the-fly so we don't need to generate them beforehand
            openssl dhparam -out dh.pem $DH_KEY_SIZE &>/dev/null 
        fi

        ./easyrsa build-server-full "$SERVER_NAME" nopass &>/dev/null
        ./easyrsa gen-crl &>/dev/null

        case $TLS_SIG in
            1 )
                # Generate tls-crypt key
                bar "openvpn --genkey --secret /etc/openvpn/tls-crypt.key"
                ;;
            2 )
                # Generate tls-auth key
                bar "openvpn --genkey --secret /etc/openvpn/tls-auth.key"
                ;;
        esac
    else
        cd /etc/openvpn/easy-rsa/ || return
        SERVER_NAME=$(cat SERVER_NAME_GENERATED)
    fi

    # move all files
    cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/easy-rsa/pki/private/ca.key "/etc/openvpn/easy-rsa/pki/issued/$SERVER_NAME.crt" "/etc/openvpn/easy-rsa/pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
    if [[ "$DH_TYPE" -eq 2 ]];then
        cp /etc/openvpn/easy-rsa/dh.pem /etc/openvpn
    fi

    chmod 644 /etc/openvpn/crl.pem

    echo -e "port $PORT\nproto $PROTOCOL" >/etc/openvpn/server.conf

    echo -e "dev tun\nuser nobody\ngroup $NOGROUP\npersist-key\npersist-tun\nkeepalive 10 120\ntopology subnet\nserver 10.8.0.0 255.255.255.0\nifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf

    # DNS resolvers
    case $DNS in
        1) # DNS System
            if (grep -q "127.0.0.53" "/etc/resolv.conf" );then
                RESOLVCONF='/run/systemd/resolve/resolv.conf'
            else
                RESOLVCONF='/etc/resolv.conf'
            fi
            sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line;do
                # Copy, if it's a IPv4 |or| if IPv6 is enabled, IPv4/IPv6 does not matter
                if [[ $line =~ '^[0-9.]*$' ]];then
                    echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
                fi
            done
            ;;
        2 ) #self hosted
            echo 'push "dhcp-option DNS 10.8.0.1"' >>/etc/openvpn/server.conf
            ;;
        3 ) #cloudflare
            echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
            echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
            ;;
        4 ) # openDNS
            echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
            echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
            ;;
        5 )
            echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
            echo 'push "dhcp-option DNS 8.4.4.8"' >>/etc/openvpn/server.conf
            ;;
        6 )
            echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server.conf
            echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server.conf
            ;;
        7 ) #custom
            echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server.conf
            if [[ !  -z "$DNS2" ]];then
                echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server.conf
            fi
            ;;
    esac
    echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf

    if [[ "$DH_TYPE" -eq 1 ]];then
        echo "dh none" >>/etc/openvpn/server.conf
        echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
    fi

    case $TLS_SIG in
        1 )
            echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
            ;;
        2 )
            echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
            ;;
    esac

    echo -e "crl-verify crl.pem\nca ca.crt\ncert $SERVER_NAME.crt\nkey $SERVER_NAME.key\nauth $HMAC_ALG\ncipher $CIPHER\nncp-ciphers $CIPHER\ntls-server\ntls-version-min 1.2\ntls-cipher $CC_CIPHER\nclient-config-dir /etc/openvpn/ccd\nstatus /var/log/openvpn/status.log\nverb s" >>/etc/openvpn/server.conf

    # Create client-config-dir dir
    mkdir -p /etc/openvpn/ccd
    # Create log dir
    mkdir -p /var/log/openvpn

    echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
    sysctl --system &>/dev/null

    # if sestatus | grep "Current mode" | grep -qs "enforcing"
    # if [[ $PORT != '1194' ]]
    # semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
    # end
    # end

    bar "systemctl daemon-reload"
    bar "systemctl enable openvpn@server"
    bar "systemctl restart openvpn@server"

    if [[ "$DNS" -eq 2 ]];then
        installUnbound
    fi
    mkdir -p /etc/iptables
    # script to add rules
    echo -e "#!/bin/sh\niptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE\niptables -I INPUT 1 -i tun0 -j ACCEPT\niptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT\niptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT\niptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh
    # script to remove rules
    echo -e "#!/bin/sh\niptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE\niptables -D INPUT -i tun0 -j ACCEPT\niptables -D FORWARD -i $NIC -o tun0 -j ACCEPT\niptables -D FORWARD -i tun0 -o $NIC -j ACCEPT\niptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

    chmod +x /etc/iptables/add-openvpn-rules.sh
    chmod +x /etc/iptables/rm-openvpn-rules.sh

    echo -e "[Unit]\nDescription=iptables rules for OpenVPN\nBefore=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/etc/iptables/add-openvpn-rules.sh\nExecStop=/etc/iptables/rm-openvpn-rules.sh\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

    # Enable service and apply rules
    bar "systemctl daemon-reload"
    systemctl enable iptables-openvpn
    bar "systemctl start iptables-openvpn"

    if [[ ! -z "$ENDPOINT" ]];then
        IP=$ENDPOINT
    fi

    echo client >/etc/openvpn/client-template.txt

    if [[ "$PROTOCOL" == "udp" ]];then
        echo "proto udp" >>/etc/openvpn/client-template.txt
        echo explicit-exit-notify >>/etc/openvpn/client-template.txt
    else
        echo "proto tcp-client" >>/etc/openvpn/client-template.txt
    fi

    echo -e "remote $IP $PORT\ndev tun\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\nverify-x509-name $SERVER_NAME name\nauth $HMAC_ALG\nauth-nocache\ncipher $CIPHER\ntls-client\ntls-version-min 1.2\ntls-cipher $CC_CIPHER\nignore-unknown-option block-outside-dns\nsetenv opt block-outside-dns # Prevent Windows 10 DNS leak\nverb 3" >>/etc/openvpn/client-template.txt
    info "Openvpn configurado correctamente!."
    read -p "Pulsa una tecla para continuar..."
}

newClient() {
    trap ctrl_c SIGINT SIGTERM
    while true;do

        read -rp '[*] Nombre del cliente: ' CLIENT

        if [[ ${#CLIENT} -ge 32 ]];then
            error "El nombre del cliente no puede tener más de 32 caracteres."
            continue
        fi
        if (grep -E '^[a-zA-Z0-9_-]+$' <<< $CLIENT &>/dev/null );then
            sqlite3 $db_ovpn "SELECT nombre FROM ovpn WHERE nombre='$CLIENT'" | grep -c "$CLIENT" &>/dev/null
            if [[ "$?" = 0 ]];then
                error "El cliente $CLIENT ya existe"
                continue
            else
                break
            fi
            break
        else
            error "El nombre del cliente solo puede contener letras, números, guiones y guiones bajos"
            continue
        fi
    done
    echo -e "$green [ 1 ] $white Agregar usuario sin contraseña"
    echo -e "$green [ 2 ] $white Agregar usuario con contraseña"
    read -rp '[*] Seleccione una opción [1-2]: ' -e -i "1" PASS

    cd /etc/openvpn/easy-rsa/ || return
    case $PASS in
        1 )
            ./easyrsa build-client-full "${CLIENT}" nopass &>/dev/null || {
                error "Error al crear el cliente $CLIENT"
                return 1
            }
            ;;
        2 )
            info "A continucacion,se le pedira la contraseña del cliente"
            ./easyrsa build-client-full "${CLIENT}" || {
                error "Error al crear el cliente."
                info "Comprueba que la contraseña este bien escrita."
                return 1
            }
            ;;
        * )
            error "La opción seleccionada no es valida.Por omisión se agregara el cliente sin contraseña."
            ./easyrsa build-client-full "${CLIENT}" nopass &>/dev/null || {
                error "Error al crear el cliente $CLIENT"
                return 1
            }
            ;;
    esac

    while true;do
        read -p "$(echo -e $GREEN'[*] Cantidad de dias para expirar : ' )" date_exp
        if [[ -z "$date_exp" ]];then
            info "Valor incorrecto, se asignara una fecha de expiracion de 1 dia."
            date_exp=1
        elif [ -z "${date_exp}" ] || [ ! grep -E '^[0-9]+$' <<< "${date_exp}" 2>/dev/null ] || [ "${date_exp}" == 0 ];then
            info 'El valor no es correcto.'
            continue
        else
            exp_date_d=$(date -d "$exp_date days" +%Y-%m-%d 2>/dev/null)
            break
        fi
    done

    sqlite3 $db_ovpn "INSERT INTO ovpn (nombre, exp_date) VALUES ('$CLIENT', '$exp_date_d')" 

    if [[ $? -eq 0 ]];then
        # Determine if we use tls-auth or tls-crypt
        if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then TLS_SIG="1"
	    elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then TLS_SIG="2" ; fi
        # Generates the custom client.ovpn
	    mkdir -p "${user_folder}/ovpn-cfg/" &> /dev/null
	    cp /etc/openvpn/client-template.txt "${user_folder}/ovpn-cfg/$CLIENT.ovpn"
	    {
	    	echo "<ca>"
	    	cat "/etc/openvpn/easy-rsa/pki/ca.crt"
	    	echo "</ca>"

	    	echo "<cert>"
	    	awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
	    	echo "</cert>"

	    	echo "<key>"
	    	cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
	    	echo "</key>"

	    	case $TLS_SIG in
	    	1)
	    		echo "<tls-crypt>"
	    		cat /etc/openvpn/tls-crypt.key
	    		echo "</tls-crypt>"
	    		;;
	    	2)
	    		echo "key-direction 1"
	    		echo "<tls-auth>"
	    		cat /etc/openvpn/tls-auth.key
	    		echo "</tls-auth>"
	    		;;
	    	esac
	    } >>"${user_folder}/ovpn-cfg/$CLIENT.ovpn"
        echo -e "\n$green [!] CLIENTE AGREGADO CORRECTAMENTE."
        info "La configuracion se guardo en \\033[32m${user_folder}/ovpn-cfg/$CLIENT.ovpn\\033[m ."
        echo ""
        read -p "Pulsa una tecla para continuar..."
        option_menu_ovpn
    else
        error "Error al agregar el cliente"
    fi

}

removeClient() {
    trap ctrl_c SIGINT SIGTERM
    while true;do
        read -rp '[*] ID del cliente a eliminar: ' -e id_client
        if (grep -E '^[0-9]+$' <<< $id_client &>/dev/null );then
            local CLIENT=$(sqlite3 $db_ovpn "SELECT nombre FROM ovpn WHERE rowid='$id_client'")
            if [[ -z "${CLIENT}" ]];then error "El cliente con el id $id_client no existe" ; continue ; else break ; fi
        
        else
            continue
        fi

    done
    cd /etc/openvpn/easy-rsa/ || return
    ./easyrsa --batch revoke "$CLIENT" &>/dev/null
    if [[ $? -eq 0 ]];then
        sqlite3 $db_ovpn "DELETE FROM ovpn WHERE nombre='$CLIENT'" &>/dev/null
        EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl &>/dev/null
	    rm -f /etc/openvpn/crl.pem
	    cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
	    chmod 644 /etc/openvpn/crl.pem
	    find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	    rm -f "/root/$CLIENT.ovpn"
	    sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt
	    cp /etc/openvpn/easy-rsa/pki/index.txt{,.bk}
        rm "${user_folder}/ovpn-cfg/$CLIENT.ovpn"
        info "El cliente $CLIENT ha sido eliminado."
        option_menu_ovpn
    else
        error "Error al eliminar el cliente $CLIENT"
    fi
}

remove_openvpn() {
    PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
	PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2) 

    # Stop OpenVPN
	bar "systemctl disable openvpn@server"
	bar "systemctl stop openvpn@server"

    # remove iptables rules
    bar "systemctl stop iptables-openvpn"
    bar "systemctl disable iptables-openvpn"
	rm /etc/systemd/system/iptables-openvpn.service &>/dev/null
	bar "systemctl daemon-reload"
	rm /etc/iptables/add-openvpn-rules.sh &>/dev/null
	rm /etc/iptables/rm-openvpn-rules.sh &>/dev/null

    bar "apt-get remove --purge -y openvpn"
    if [[ -f /etc/apt/sources.list.d/openvpn.list ]];then
        rm /etc/apt/sources.list.d/openvpn.list
		bar "apt-get update"
    fi

    # Cleanup
	find /home/ -maxdepth 2 -name "*.ovpn" -delete &>/dev/null
	find /root/ -maxdepth 1 -name "*.ovpn" -delete &>/dev/null
	rm -rf /etc/openvpn &>/dev/null
	rm -rf "/usr/share/doc/openvpn*" &>/dev/null
	rm -f /etc/sysctl.d/99-openvpn.conf &>/dev/null
	rm -rf /var/log/openvpn &>/dev/null

    if [[ -f /etc/unbound/openvpn.conf ]] ;then
        removeUnbound
    fi

    # remove database
    sqlite3 $db_ovpn "DROP TABLE ovpn" 2>/dev/null

    info "OpenVPN ha sido eliminado."
    exit 0
}

option_menu_ovpn() {
    clear
    list_users_ovpn
    option_color "1" "AGREGAR NUEVO USUARIO"
    option_color '2' "REMOVER USUARIO"
    option_color '3' "CONFIGURAR OPENVPN"
    option_color 'E' "SALIR"
    option_color 'M' "MENU PRINCIPAL"
    while true;do
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " option
        case $option  in
            1 )
                newClient
                ;;
            2 )
                removeClient
                ;;
            3 )
              cgf_openvpn
              ;;
            e | E | q )
                exit
                ;;
            m | M )
                fenix
                ;;
            "cls" | "CLS" )
                clear
                option_menu_ovpn
                ;;
        esac
    done
}

list_users_ovpn() {
    create_db_user_ovpn
    users_vars=$(sqlite3 $db_ovpn "SELECT rowid,nombre, exp_date FROM ovpn" )
    line_separator 70
    printf "${BLUE}〢${WHITE} [%-1s] ${RED}%-32s ${YELLOW}%-10s ${BLUE}%26s\n" "#" "Nombre" "Expira" '〢'
    line_separator 70
    for i in $users_vars;do
        IFS='|' read -r -a user_array <<< "$i"
        local id user exp tmp
        
        id="${user_array[0]}"        
        user="${user_array[1]}"
        exp="${user_array[2]}"
        
        [[ ${#user} -gt 25 && ${columns} -lt 100 ]] && {
            # ! (...)
            user="${user:0:20}(...)"
        }
        printf "${BLUE}〢${WHITE} [%-${#id}s] ${RED}%-32s ${YELLOW}%-10s ${BLUE}%26s\n" "${id}" "${user}" "${exp}" '〢'
    done
    line_separator 70
    local config_files_dir="${user_folder}/ovpn-cfg"
    printf "${WHITE}〢 %-7s ${GREEN}%-${#config_files_dir}s ${WHITE}%$(echo 72 - 8 - ${#config_files_dir} | bc )s\n" "DIR-CFG:" "${config_files_dir}" '〢'
    line_separator 70

}

main() {
    if [[ -d /dev/net/tun ]];then
        error "TUN/TAP no está disponible. Verifique que el TUN/TAP esté activado."
        exit 1
    fi
    ovpn_is_installed=$(dpkg-query -W --showformat='${Status}\n' openvpn 2>/dev/null| grep -c "install ok installed")
    if [[ -e /etc/openvpn/server.conf ]] && [[ "$ovpn_is_installed" = "1" ]];then
        manageMenu
    else
        install_openvpn
    fi
}