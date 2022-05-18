#!/usr/bin/bash

source "/etc/FenixManager//preferences.bash" 2>/dev/null
source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/color.bash" 2>/dev/null

script_executed_with_root_privileges


v2ray_and_x_ui_installed_or_running(){
    v2ray_is_running=$(systemctl status v2ray &>/dev/null; echo $?)
    x_ui_is_running=$(systemctl status x-ui &>/dev/null; echo $?)

    if [ -e "/usr/bin/x-ui" ];then x_ui_is_installed=0 ; else x_ui_is_installed=1  ;  fi
    # re check if v2ray is installed
    if [[ -f "/usr/local/bin/v2ray" ]];then v2ray_installed=0 ; else v2ray_installed=1 ; fi 
}

des_install_v2ray_core() {
    local opt="$1"
    clear
    if [[ $opt == "1" ]];then
        echo -e "${BLUE}〢───────────────〢 ${WHITE}INSTALANDO V2RAY-CORE${BLUE} 〢──────────────────〢"
        bash -c "/etc/FenixManager/funciones/v2ray/v2ray-install-release.bash"
        cfg_v2ray
    else
        separator "DESINSTALANDO V2RAY-CORE"
        bash -c "/etc/FenixManager/funciones/v2ray/v2ray-install-release.bash --remove"
    fi

}

install_v2ray_web_manager(){
    trap ctrl_c SIGINT SIGTERM
    clear
    echo -e "${BLUE}〢───────────〢 ${WHITE}INSTALANDO V2RAY-WEB-MANAGER${BLUE} 〢───────────────〢"
    bash <(curl -L -s https://raw.githubusercontent.com/M1001-byte/x-ui-spanish/main/install.sh)
    read -r -p "Presione una tecla para continuar..."
}

cfg_v2ray(){
    # Relamente me da flojera crear todo un menu en bash para administrar v2ray.
    # Es por eso que me tome el trabajo de traducir el panel webui. ( chino a espanol ).
    v2ray_and_x_ui_installed_or_running
    clear
    #separator "CONFIGURANDO V2RAY"
    echo -e "${BLUE}〢─────────────────〢 ${WHITE}CONFIGURANDO V2RAY${BLUE} 〢───────────────────〢"
    show_status_v2ray_xui
    
    # x-ui-is-installed
    if [[ $x_ui_is_installed -eq 0 ]];then
        option_color 1 "ADMINISTRAR X-UI ( Panel web )"
    else
        info "Instalar en panel web es altamente recomendado. Sin el: usted tendra que configurar v2ray de forma manual."
        echo -e ""
        option_color 1 "INSTALAR V2RAY-WEBUI ( PANEL WEB PARA CONFIGURAR V2RAY )"
    fi
    
    if [[ $v2ray_is_running == 0 ]] ; then
        option_color 2 "REINICIAR V2RAY"
        option_color 3 "DETENER V2RAY"
        option_color 4 "VER ESTADO DE V2RAY"
        option_color 5 "DESINSTALAR V2RAY"
    else
        option_color 2 "INICIAR V2RAY"
        option_color 3 "VER ESTADO DE V2RAY"
        option_color 4 "DESINSTALAR V2RAY"
    fi
    option_color B "MENU DE INSTALACION DE SOFTWARE"
    option_color E "SALIR"

    while true;do
        trap ctrl_c SIGINT SIGTERM
        prompt=$(date "+%x %X")
        read -r -p "$(echo -e "${WHITE}[${BBLUE}${prompt}${WHITE}")] : " user_option

        case $user_option in
            1) # INSTALAR/ADMINISTRAR V2RAY-WEBUI
                if [[ ! $x_ui_is_installed -eq 0 ]];then
                    install_v2ray_web_manager
                else
                    cfg_x_ui
                fi
                ;;
            2) # REINICIAR/INICIAR V2RAY
                if [[ $v2ray_is_running == 0 ]] ; then
                    bar "systemctl restart v2ray"
                    sleep 2.5
                else
                    bar "systemctl start v2ray"
                    sleep 2.5
                fi
                ;;
            3) # DETENER / VER ESTADO DE V2RAY
                if [[ $v2ray_is_running == 0 ]] ; then
                    bar "systemctl stop v2ray"
                    sleep 2.5
                    cfg_v2ray
                else
                    systemctl status v2ray
                    sleep 2.5
                fi
                ;;
            4) # VER ESTADO / DESINSTALAR
                if [[ $v2ray_is_running == 0 ]] ; then
                    systemctl status v2ray
                else
                    des_install_v2ray_core 2
                fi
                ;;
            5) # DESINSTALAR V2RAY
                des_install_v2ray_core 2
                break
                ;;
            
            "clear"|"cls"|"Clear")
                clear
                cfg_v2ray
                ;;
            [Bb])
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

cfg_x_ui(){
    clear
    v2ray_and_x_ui_installed_or_running
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
            1) # REINICIAR/INICIAR X-UI
                [[ $x_ui_is_running == 0 ]] && bar "systemctl restart x-ui" || bar "systemctl start x-ui"
                sleep 2.5
                cfg_x_ui
                ;;
            2) # DETENER/VER ESTADO X-UI
                [[ $x_ui_is_running == 0 ]] && bar "systemctl stop x-ui" || systemctl status x-ui
                sleep 2.5
                cfg_x_ui
                ;;
            3) # DESINSTALAR/VER ESTADO DE X-UI
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
                    read -p "$(echo -e "${YELLOW}[*] Estas seguro de querer restablecer la contraseña y usuario a los valored por defectos? [y/n] : ")" user_option
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
                    read -p "$(echo -e "${YELLOW}[*] ¿Está seguro de que desea restablecer todas las configuraciones del panel, los datos de la cuenta no se perderán, el nombre de usuario y la contraseña no se cambiarán? [y/n] : ")" user_option
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
    if [[ $v2ray_is_running -eq 0 ]];then
        v2ray_string="[ EN EJECUCION ]"
        color_1="${GREEN}"

    elif [[ $v2ray_installed -eq 1 ]];then
        v2ray_string="[ NO INSTALADO ]"
        color_1="${RED}"
    else
        v2ray_string="[ DETENIDO ]"
        color_1="${RED}"
    fi
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
    
    printf "${WHITE}〢 V2RAY : ${color_1}${v2ray_string}${WHITE} %${one_length}s\n" "〢"
    printf "${WHITE}〢 PANEL WEB : ${color_2}${x_ui_string}${WHITE} %${two_length}s\n" "〢"
    line_separator 60
}
show_web_panel_info(){
    local log_cmd username password
    local port_to_bind=$(systemctl status x-ui 2>/dev/null | grep -o  "web server run http on .*" | awk '{split($0,a,":"); print a[4]}')
    local username=$(sqlite3 /etc/x-ui/x-ui.db "select username from users" )
    local password=$(sqlite3 /etc/x-ui/x-ui.db "select password from users" )
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