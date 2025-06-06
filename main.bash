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
    echo '<font color=#0000FF>〢 ──────────────────────── 〢</font><br><b><font color=#FFFFFF>〢 Script: </font><font color=#FF0000>FenixManager</font><font color=FFFFFF> 〢<br><font color=#FFFFFF>〢 Version: </font><font color=#FF0000>replace_version</font><font color=#FFFFFF> 〢</font><br><font color=#FFFFFF>〢 Dev: </font><font color=#FF00FF>git@M1001_byte</font><font color=#FFFFFF> 〢</font><br><font color=#FFFFFF>〢 Github: </font><font color=#FF0000>github.com/M1001-byte/FenixManager</font><font color=#FFFFFF> 〢</font><br><font color=#FFFFFF>〢 Telegram: </font><font color=#FFFF00>@Mathiue1001</font><font color=#FFFFFF> 〢</font><br><font color=#0000FF>〢 ──────────────────────── 〢</font><br><font color=#FFFFFF>〢<font color=#008000>Gracias por utilizar FenixManager! <font color=#FFFFFF>〢</font></b>' \
    | sed -e 's/replace_version/'"${v}"'/g' > "$ssh_banner"

    config_sshd='UG9ydCAyMgpQcm90b2NvbCAyCktleVJlZ2VuZXJhdGlvbkludGVydmFsIDM2MDAKU3lzbG9nRmFjaWxpdHkgQVVUSApMb2dMZXZlbCBJTkZPCkxvZ2luR3JhY2VUaW1lIDEyMApQZXJtaXRSb290TG9naW4geWVzClN0cmljdE1vZGVzIHllcwpQdWJrZXlBdXRoZW50aWNhdGlvbiB5ZXMKSWdub3JlUmhvc3RzIHllcwpSaG9zdHNSU0FBdXRoZW50aWNhdGlvbiB5ZXMKSG9zdGJhc2VkQXV0aGVudGljYXRpb24geWVzClBlcm1pdEVtcHR5UGFzc3dvcmRzIG5vCkNoYWxsZW5nZVJlc3BvbnNlQXV0aGVudGljYXRpb24gbm8KUGFzc3dvcmRBdXRoZW50aWNhdGlvbiB5ZXMKUGVybWl0VHVubmVsIHllcwpYMTFGb3J3YXJkaW5nIHllcwpYMTFEaXNwbGF5T2Zmc2V0IDEwClByaW50TW90ZCBubwpQcmludExhc3RMb2cgeWVzCkRlYmlhbkJhbm5lciBubwpUQ1BLZWVwQWxpdmUgbm8KQ2xpZW50QWxpdmVJbnRlcnZhbCAzMDAKQ2xpZW50QWxpdmVDb3VudE1heCAzCkFjY2VwdEVudiBMQU5HIExDXyoKU3Vic3lzdGVtIHNmdHAgL3Vzci9saWIvb3BlbnNzaC9zZnRwLXNlcnZlcgpVc2VQQU0geWVzCg=='

    info "Agregando configuracion al archivo ${GREEN}$sshd_file"
    cp "$sshd_file" "$sshd_file.bak" 2> /dev/null
    echo -e $config_sshd | base64 -d > $sshd_file || error "No se pudo crear/modificar el archivo $sshd_file."  && echo "Banner $ssh_banner" >> $sshd_file
    
    bar "systemctl reload ssh"
    bar "systemctl reload sshd" || {
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
    info "${RED}Tomate el tiempo de leer todo lo que se muestra en pantalla.${WHITE}(${WHITE} ${RED}Es de utilidad ${WHITE})"
    info "Presione enter para continuar"
    read 
    install_badvpn_udpgw
    echo -e "${BLUE}| ────────────── | ${WHITE}FIN DE LA INSTALACION${BLUE} | ─────────────────── |"
    info "Su vps tendra el ultimo proceso de reincio para terminar con la instalacion."
    read -p 'Presione enter para continuar...'
    reboot
}

main