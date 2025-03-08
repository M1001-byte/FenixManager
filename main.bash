#!/bin/bash

source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/install-pkt.bash"
source "/etc/FenixManager/preferences.bash" || {
    echo "No se pudo cargar el archivo de preferencias."
    echo "Vuelva a instalar FenixManager."
    exit 1
}

script_executed_with_root_privileges

config_sshd () {
    trap "exit 130" SIGINT SIGTERM
    echo -e "${BLUE}| ──────────────────── | ${WHITE}CONFIGURANDO SSHD${BLUE} | ───────────────── |"
    mkdir "$user_folder/FenixManager/banner" &> /dev/null
    local ssh_banner="$user_folder/FenixManager/banner/fenix.html"
    local v="$(cat /etc/FenixManager/version 2>/dev/null)"
    local sshd_file="/etc/ssh/sshd_config"
    echo '<strong style="color:#0066cc;font-size: 30px;">〢 ────────────────────────〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Script: </strong><strong style="color:#ff0000;font-size: 30px;">FenixManager</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Version: </strong><strong style="color:#ff0000;font-size: 30px;">replace_version</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Dev: </strong><strong style="color:#ff0000;font-size: 30px;">@M1001_byte</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Github: </strong><strong style="color:#ff0000;font-size: 30px;">github.com/M1001-byte/FenixManager</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Telegram: </strong><strong style="color:#ff0000;font-size: 30px;">@M1001-byte</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢 Telegram: </strong><strong style="color:#ff0000;font-size: 30px;">@Mathiue1001</strong><strong style="color:#FFFFFF;font-size: 30px;"> 〢</strong><br><strong style="color:#0066cc;font-size: 30px;">〢 ────────────────────────〢</strong><br><strong style="color:#FFFFFF;font-size: 30px;">〢Gracias por utilizar FenixManager!〢</strong>' \
    | sed -e 's/replace_version/'"${v}"'/g' > "$ssh_banner"

    config_sshd='UG9ydCAyMgpQcm90b2NvbCAyCktleVJlZ2VuZXJhdGlvbkludGVydmFsIDM2MDAKU3lzbG9nRmFjaWxpdHkgQVVUSApMb2dMZXZlbCBJTkZPCkxvZ2luR3JhY2VUaW1lIDEyMApQZXJtaXRSb290TG9naW4gbm8KU3RyaWN0TW9kZXMgeWVzClB1YmtleUF1dGhlbnRpY2F0aW9uIHllcwpJZ25vcmVSaG9zdHMgeWVzClJob3N0c1JTQUF1dGhlbnRpY2F0aW9uIG5vCkhvc3RiYXNlZEF1dGhlbnRpY2F0aW9uIG5vClBlcm1pdEVtcHR5UGFzc3dvcmRzIG5vCkNoYWxsZW5nZVJlc3BvbnNlQXV0aGVudGljYXRpb24gbm8KUGFzc3dvcmRBdXRoZW50aWNhdGlvbiBubwpQZXJtaXRUdW5uZWwgeWVzClgxMUZvcndhcmRpbmcgbm8KWDExRGlzcGxheU9mZnNldCAxMApQcmludE1vdGQgbm8KUHJpbnRMYXN0TG9nIHllcwpEZWJpYW5CYW5uZXIgbm8KVENQS2VlcEFsaXZlIG5vCkNsaWVudEFsaXZlSW50ZXJ2YWwgMzAwCkNsaWVudEFsaXZlQ291bnRNYXggMwpBY2NlcHRFbnYgTEFORyBMQ18qClN1YnN5c3RlbSBzZnRwIC91c3IvbGliL29wZW5zc2gvc2Z0cC1zZXJ2ZXIKVXNlUEFNIHllcwo='

    info "Agregando configuracion al archivo ${GREEN}$sshd_file"
    cp "$sshd_file" "$sshd_file.bak" 2> /dev/null
    echo -e $config_sshd | base64 -d > $sshd_file || error "No se pudo crear/modificar el archivo $sshd_file."  && echo "Banner $ssh_banner" >> $sshd_file
    bar "systemctl reload sshd" || {
        bar "systemctl reload ssh"
        error "No se pudo reiniciar el servicio sshd."
        info "Esto cambio el algunas distribuciones mas recientes de Ubuntu. No es para procuparse."
    } && info "${GREEN}SSHD Configurado con exito."

}

fail2ban_config () {
    trap "exit 130" SIGINT SIGTERM
    echo -e "${BLUE}| ────────────────── | ${WHITE}CONFIGURANDO FAIL2BAN${BLUE} | ─────────────── |"
    local fail2ban_dir_config='/etc/fail2ban'
    info "Configurando fail2ban ${GREEN}$fail2ban_dir_config/jail.conf/"

    cp "$fail2ban_dir_config/jail.conf" "$fail2ban_dir_config/jail.conf.bak" # backup

    local fai2lban_config='[sshd]\nport = ssh\nenabled = true\nmaxretry = 4\nbantime = 10m\nfindtime = 10m\n[dropbear]\nport = dropbear\nenabled = true\nmaxretry = 4\nbantime = 15m\nfindtime = 10m\n'

    echo -e "$fai2lban_config" > "$fail2ban_dir_config/jail.conf" || error "No se pudo crear/modificar el archivo $fail2ban_dir_config/jail.conf."
    service fail2ban restart
    info "${GREEN}FAIL2BAN configurado con exito."
}

config_bbr() {
    trap "exit 130" SIGINT SIGTERM
    local sysctl_file='/etc/sysctl.conf'
    echo -e "${BLUE}| ──────────────────── | ${WHITE}SYSCTL 'TWEAKS'${BLUE} | ─────────────────── |"

    cp $sysctl_file "$sysctl_file.bak" # backup
    modprobe tcp_bbr
    echo -e '# Enabled BBR google' >> $sysctl_file
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    info "${GREEN}BBR ${WHITE}habilitado con exito."
    echo "net.ipv4.tcp_fastopen=3" >> /etc/sysctl.conf
    info "${GREEN}TCP FAST OPEN${WHITE} habilitado con exito."
}

sqlite3_config () {
    trap "exit 130" SIGINT SIGTERM
    mkdir -p /etc/FenixManager/database/ &> /dev/null
    usuariosdb='/etc/FenixManager/database/usuarios.db'
    logfile='/var/log/FenixManager/sqlite.log'

    echo -e "${BLUE}| ─────────────────── | ${WHITE}CONFIGURANDO SQLITE3${BLUE} | ─────────────── |"

    info "Creando base de datos con el nombre de '${YELLOW}usuarios${WHITE}'"
    rm /etc/FenixManager/database/usuarios.db &>/dev/null
    touch $usuariosdb &>/dev/null
    if [[ $status -eq 0 ]];then
        info 'La base de datos se creo con exito.'
    else
        error 'Fallo al crear la base de datos.'
        exit 1
    fi

    info "Creando la tabla '${YELLOW}ssh${WHITE}' dentro de la base de datos '${YELLOW}usuarios${WHITE}'"
    sqlite3 $usuariosdb  'CREATE TABLE ssh (nombre VARCHAR(32) NOT NULL, alias VARCHAR(15), password VARCHAR(20), exp_date DATETIME, max_conn INT NOT NULL );'
    info "${GREEN}SQLITE3${WHITE} configurada con exito."
}

add_alias_to_fenix () {
    trap "exit 130" SIGINT SIGTERM
    echo -e "${BLUE}| ─────────────── | ${WHITE}INSTALANDO FENIXMANAGER${BLUE} | ──────────────── |"
    
    cp "/etc/FenixManager/bin/fenix" /usr/bin/fenix && chmod 777 /usr/bin/fenix
    echo -e "unalias fenix 2>/dev/null" >> "${user_folder}/.bashrc"
    
    local preferences_var="hide_first_panel='false'\nhide_second_panel='false'\nhide_third_panel='false'\nhide_fourth_panel='false'\nhide_ports_open_services_in_home_menu='false'\nhide_ports_open_services_in_protocol_menu='false'"
    echo -e "$preferences_var" >> "/etc/FenixManager/preferences.bash"
}

fenix_create_cfg_dir(){
    trap "exit 130" SIGINT SIGTERM
    echo -e "${BLUE}| ────────────────── | ${WHITE}CREANDO DIRECTORIOS${BLUE} | ───────────────── |"
    echo -e "${GREEN}${user_folder}/FenixManager/${WHITE} : Archivos de configuracion. ( pysocks,slowdns_pub, etc )"
    echo -e  "${GREEN}${user_folder}/FenixManager/banner${WHITE} : Banners de ssh/dropbear."
    echo -e  "${GREEN}${user_folder}/FenixManager/cert-ssl${WHITE} : Certificados SSL."
    echo -e  "${GREEN}/etc/FenixManager/${WHITE} : Directorio root de FenixManager. ( ${RED}NO MODIFICAR NINGUN ARCHIVO${WHITE} )"
    echo -e  "${GREEN}/etc/FenixManager/database/usuarios.db${WHITE} : Archivo de la base de datos. ( SSH , OVPN, ETC )"
    mkdir -p ${user_folder}/FenixManager/{banner,cert-ssl} & > /dev/null
    
    local user_login=$(logname)
    chown -R "${user_login}" "${user_folder}/FenixManager" &> /dev/null

    local public_ip=$(curl -s http://api.ipify.org )
    echo "${public_ip}" > "/etc/FenixManager/ip"
}
main(){
    clear
    print_banner
    fenix_create_cfg_dir
    config_sshd
    fail2ban_config
    config_bbr
    sqlite3_config
    add_alias_to_fenix
    add_cron_job_for_hitman
    install_badvpn_udpgw
    echo -e "${BLUE}| ────────────── | ${WHITE}FIN DE LA INSTALACION${BLUE} | ─────────────────── |"
    info "${RED}Tomate el tiempo de leer todo lo que se muestra en pantalla.${WHITE}(${WHITE} ${RED}Es de utilidad ${WHITE})"
    info "Su session de usuario se cerrara automaticamente,para terminar con el proceso de instalacion."
    read -p 'Presione enter para continuar...'
    pkill -u "$(logname)"
}

main