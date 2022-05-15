#!/usr/bin/bash

source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/preferences.bash"

script_executed_with_root_privileges

config_sshd () {
    trap "exit 130" SIGINT SIGTERM
    echo -e "${BLUE}〢────────────────────〢 ${WHITE}CONFIGURANDO SSHD${BLUE} 〢─────────────────〢"
    mkdir "$user_folder/FenixManager/banner" &> /dev/null
    ssh_banner="$user_folder/FenixManager/banner/fenix.html"
    sshd_file="/etc/ssh/sshd_config"
    echo "<strong>FenixManager V1.0</strong>" > $ssh_banner

    config_sshd='SW5jbHVkZSAvZXRjL3NzaC9zc2hkX2NvbmZpZy5kLyouY29uZgpQb3J0IDIyCkFkZHJlc3NGYW1pbHkgaW5ldApMaXN0ZW5BZGRyZXNzIDAuMC4wLjAKTG9naW5HcmFjZVRpbWUgMm0KUGVybWl0Um9vdExvZ2luIHllcwpNYXhBdXRoVHJpZXMgMwpQYXNzd29yZEF1dGhlbnRpY2F0aW9uIHllcwpQZXJtaXRFbXB0eVBhc3N3b3JkcyBubwpDaGFsbGVuZ2VSZXNwb25zZUF1dGhlbnRpY2F0aW9uIG5vClVzZVBBTSB5ZXMKQWxsb3dUY3BGb3J3YXJkaW5nIHllcwpLZXhBbGdvcml0aG1zIGN1cnZlMjU1MTktc2hhMjU2QGxpYnNzaC5vcmcsZWNkaC1zaGEyLW5pc3RwNTIxLGVjZGgtc2hhMi1uaXN0cDM4NCxlY2RoLXNoYTItbmlzdHAyNTYsZGlmZmllLWhlbGxtYW4tZ3JvdXAtZXhjaGFuZ2Utc2hhMjU2CkNpcGhlcnMgY2hhY2hhMjAtcG9seTEzMDVAb3BlbnNzaC5jb20sYWVzMjU2LWdjbUBvcGVuc3NoLmNvbSxhZXMxMjgtZ2NtQG9wZW5zc2guY29tLGFlczI1Ni1jdHIsYWVzMTkyLWN0cixhZXMxMjgtY3RyCk1BQ3MgaG1hYy1zaGEyLTUxMi1ldG1Ab3BlbnNzaC5jb20saG1hYy1zaGEyLTI1Ni1ldG1Ab3BlbnNzaC5jb20sdW1hYy0xMjgtZXRtQG9wZW5zc2guY29tLGhtYWMtc2hhMi01MTIsaG1hYy1zaGEyLTI1Nix1bWFjLTEyOEBvcGVuc3NoLmNvbQpYMTFGb3J3YXJkaW5nIG5vClgxMURpc3BsYXlPZmZzZXQgMApYMTFVc2VMb2NhbGhvc3Qgbm8KUHJpbnRNb3RkIG5vClByaW50TGFzdExvZyBubwpUQ1BLZWVwQWxpdmUgeWVzCkNvbXByZXNzaW9uIGRlbGF5ZWQKVXNlRE5TIHllcwpQZXJtaXRUdW5uZWwgeWVzCkFjY2VwdEVudiBMQU5HIExDXyoKWDExRm9yd2FyZGluZyBubwpBbGxvd1RjcEZvcndhcmRpbmcgeWVzCkRlYmlhbkJhbm5lciBubwo='

    info "Agregando configuracion al archivo ${GREEN}$sshd_file"
    
    echo -e $config_sshd | base64 -d > $sshd_file || error "No se pudo crear/modificar el archivo $sshd_file."  && echo "Banner $ssh_banner" >> $sshd_file
    systemctl restart sshd
    info "${GREEN}SSHD Configurado con exito."

}

fail2ban_config () {
    trap "exit 130" SIGINT SIGTERM
    echo -e "${BLUE}〢──────────────────〢 ${WHITE}CONFIGURANDO FAIL2BAN${BLUE} 〢───────────────〢"
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
    echo -e "${BLUE}〢────────────────────〢 ${WHITE}SYSCTL 'TWEAKS'${BLUE} 〢───────────────────〢"

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

    echo -e "${BLUE}〢───────────────────〢 ${WHITE}CONFIGURANDO SQLITE3${BLUE} 〢───────────────〢"

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
    echo -e "${BLUE}〢───────────────〢 ${WHITE}INSTALANDO FENIXMANAGER${BLUE} 〢────────────────〢"
    
    str_replace='Para terminar el proceso de instalacion.*'
    str_new='Para mostrar el panel de administracion,ejecutar el siguiente comando : \\033[32mfenix \\033[m"'
    sed -i "s/$str_replace/$str_new/" $user_folder/.bashrc
    sed -i '/alias fenix=/d' "$user_folder/.bashrc"
    cp "/etc/FenixManager/bin/fenix" /usr/bin/fenix && chmod +x /usr/bin/fenix
    

    
    local preferences_var=("show_fenix_banner=true" "hide_first_panel='false'" "hide_second_panel='false'" "hide_third_panel='false'" "hide_fourth_panel='false'" "hide_ports_open_services_in_home_menu='false'" "hide_ports_open_services_in_protocol_menu='false'")
    for i in "${preferences_var[@]}"; do echo "$i" >> "/etc/FenixManager/preferences.bash" ; done
}

fenix_create_cfg_dir(){
    trap "exit 130" SIGINT SIGTERM
    echo -e "${BLUE}〢──────────────────〢 ${WHITE}CREANDO DIRECTORIOS${BLUE} 〢─────────────────〢"
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
    add_cron_job_for_udpgw
    separator "FIN DE LA INSTALACION"
    echo -e "${BLUE}〢──────────────〢 ${WHITE}FIN DE LA INSTALACION${BLUE} 〢───────────────────〢"
    info "${RED}Tomate el tiempo de leer todo lo que se muestra en pantalla.${WHITE}(${WHITE} ${RED}Es de utilidad ${WHITE})"
    info "Se cerra la  session actual de tu usuario usuario.(${RED}NO SE REINICIARA SU VPS${WHITE} )"
    read -p 'Presione enter para continuar...'
    sleep 1.5
    clear
    pkill -u $(logname)
}

main