#!/bin/bash

source "/etc/FenixManager//preferences.bash" 2>/dev/null
source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/color.bash" 2>/dev/null

script_executed_with_root_privileges


x_ui_installed_or_running(){
    x_ui_is_running=$(systemctl status x-ui &>/dev/null; echo $?)
    local x_ui_bin=$(which x-ui)

    if [ -e "${x_ui_bin}" ];then x_ui_is_installed=0 ; else x_ui_is_installed=1  ;  fi
    # re check if v2ray is installed
}

install_x-ui(){
    trap ctrl_c SIGINT SIGTERM
    clear
    echo -e "${BLUE}〢───────────〢 ${WHITE}INSTALANDO X-UI-WEB-MANAGER${BLUE} 〢───────────────〢"
    bash <(curl -L -s https://raw.githubusercontent.com/M1001-byte/x-ui-spanish/main/install.sh)
    read -r -p "Presione una tecla para continuar..."
}

cfg_x_ui(){
    clear
    x_ui_installed_or_running
    echo -e "${BLUE}〢───────────〢 ${WHITE}CONFIGURANDO X-UI ( PANEL WEB )${BLUE} 〢────────────〢"
    show_web_panel_info
    
    
    if [[ $x_ui_is_running -eq 0 ]];then
        option_color 1 "REINICIAR X-UI"
        option_color 2 "DETENER X-UI"
        option_color 3 "VER ESTADO DE X-UI"
        option_color 4 "RESTABLECER USUARIO Y CONTRASEÑA"
        option_color 5 "RESTABLECER LA CONFIGURACION DEL PANEL"
        option_color 6 "CAMBIAR PUERTO DEL PANEL"
        option_color 7 "DESINSTALAR X-UI"
    else
        option_color 1 "INICIAR X-UI"
        option_color 2 "VER ESTADO DE X-UI"  
        option_color 3 "DESINSTALAR X-UI"
    fi
    
    option_color M "MENU DE INSTALACION DE SOFTWARE"
    option_color B "MENU ANTERIOR"
    option_color E "SALIR"
    
    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[${BBLUE}${prompt}${WHITE}")] : " user_option

        case $user_option in
            1)
             # REINICIAR/INICIAR X-UI
                [[ $x_ui_is_running == 0 ]] && bar "systemctl restart x-ui" || bar "systemctl start x-ui"
                sleep 2.5
                cfg_x_ui
                ;;
            2) 
            # DETENER/VER ESTADO X-UI
                [[ $x_ui_is_running == 0 ]] && bar "systemctl stop x-ui" || systemctl status x-ui
                sleep 2.5
                cfg_x_ui
                ;;
            3) 
            # DESINSTALAR/VER ESTADO DE X-UI
                [[ $x_ui_is_running == 0 ]] && {
                    systemctl status x-ui
                } || {
                    x-ui uninstall
                    rm /usr/bin/x-ui -f
                    sleep 2.5
                }
                ;;
            4) # RESTABLECER CONTRASEÑA DE USUARIO
                {
                    read -ep "$(echo -e "${YELLOW}[*] Estas seguro de querer restablecer la contraseña y usuario a los valored por defectos? [y/n] : ")" user_option
                    if [[ $user_option == "y" ]];then
                        /usr/local/x-ui/x-ui setting -username admin -password admin &>/dev/null
                        info "El nombre de usuario y contraseña se han restablecido a los valores por defecto. ( ${GREEN}admin ${WHITE}/ ${GREEN}admin )"
                        systemctl restart x-ui
                        sleep 2.5
                    else
                        clear
                        cfg_x_ui
                    fi
                }
                ;;
            5) # RESTABLECER LA CONFIGURACION DEL PANEL
                {
                    read -ep "$(echo -e "${YELLOW}[*] ¿Está seguro de que desea restablecer todas las configuraciones del panel, los datos de la cuenta no se perderán, el nombre de usuario y la contraseña no se cambiarán? [y/n] : ")" user_option
                    if [[ $user_option == "y" ]];then
                        /usr/local/x-ui/x-ui setting -reset &>/dev/null
                        systemctl restart x-ui
                        info "Todas las configuraciones del panel se han restablecido a los valores predeterminados."
                        sleep 2.5
                    else
                        clear
                        cfg_x_ui
                    fi
                }
                break
                ;;
            6) # CAMBIAR PUERTO DEL PANEL
                {
                    port_input
                    local new_port=${puertos_array[0]}
                    /usr/local/x-ui/x-ui setting -port ${new_port} &>/dev/null
                    systemctl restart x-ui
                    info "El puerto del panel se ha cambiado a ${GREEN}${new_port}${WHITE}."
                    sleep 1.5
                    cfg_x_ui
                }
                ;;
            7) # DESINSTALAR X-UI
                x-ui uninstall
                rm /usr/bin/x-ui -f
                break
                ;;
            
            "clear"|"cls"|"Clear")
                clear
                cfg_x_ui
                ;;
            
            [Bb])
                clear
                cfg_v2ray
                ;;
            [Mm])
                clear
                option_menu_software
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


show_status_v2ray_xui(){
    local color
    if [[ $x_ui_is_running -eq 0 ]];then
        x_ui_string="[ EN EJECUCION ]"
        color_2="${GREEN}"
    elif [[ $x_ui_is_installed -eq 1 ]];then
        x_ui_string="[ NO INSTALADO ]"
        color_2="${RED}"
    else
        x_ui_string="[ DETENIDO ]"
        color_2="${RED}"
    fi

    one_length=$(echo 61 - $(echo "V2RAY  ${v2ray_string}" | wc -c ) | bc)
    two_length=$(echo 61 - $(echo "PANEL WEB  ${x_ui_string}" | wc -c ) | bc)
    
    printf "${WHITE}〢 PANEL WEB : ${color_2}${x_ui_string}${WHITE} %${two_length}s\n" "〢"
    line_separator 60
}
show_web_panel_info(){
    local log_cmd username password
    local port_to_bind=$(systemctl status x-ui 2>/dev/null | grep -o  "web server run http on .*" | awk '{split($0,a,":"); print a[4]}')
    local username=$(sqlite3 /etc/x-ui/x-ui.db "select username from users" 2>/dev/null)
    local password=$(sqlite3 /etc/x-ui/x-ui.db "select password from users" 2>/dev/null)
    [[ -z "${username}" || -z "${password}" ]] && {
        error "No se ha configurado el usuario y contraseña del panel web."
        info "Tendra que configurarlo manualmente, ejecutando el comando de abajo."
        info "sudo x-ui setting -username <username> -password <password>"
        return 1
    }
    local url_="http://$(curl -s ipinfo.io/ip):${port_to_bind}"

    one_length=$(echo 61 - $(echo "PUERTO DEL PANEL ${port_to_bind}" | wc -c ) | bc)
    two_length=$(echo 61 - $(echo "USUARIO DEL PANEL ${username}" | wc -c ) | bc)
    three_length=$(echo 62 - $(echo "CONTRASEÑA DEL PANEL ${password}" | wc -c ) | bc)
    [[ -n "${domain_}" ]] && {
        local url_="http://${domain_}:${port_to_bind}"
    }
    printf "${WHITE}〢 %-10s: ${GREEN}%0.9s ${WHITE}%${one_length}s\n" "PUERTO DEL PANEL" "${port_to_bind}" '〢'
    printf "${WHITE}〢 %-10s: ${GREEN}%-${#username}s ${WHITE}%${two_length}s\n" "USUARIO DEL PANEL" "${username}" '〢'
    printf "${WHITE}〢 %-10s: ${GREEN}%-${#password}s ${WHITE}%${three_length}s\n" "CONTRASEÑA DEL PANEL" "${password}" '〢'
    printf "${WHITE}〢 %-5s ${GREEN}%-${#url_}s ${WHITE}%$(echo 60 - 5 - ${#url_} | bc )s\n" "URL:" "${url_}" '〢'
    line_separator 60
}