#!/bin/bash

fenixmanager_crontab="/etc/cron.d/fenixmanager"
log_file="/var/log/FenixManager/hitman.log"
db='/etc/FenixManager/database/usuarios.db'
fecha_actual=$(date "+%Y-%m-%d")

check_for_expire_ssh(){
    for user in $(sqlite3 "$db" "SELECT nombre,password,exp_date FROM ssh WHERE exp_date == '${fecha_actual}'"); do
        IFS='|' read -r -a array <<< "$user"
        sqlite3 "$db" "DELETE FROM ssh WHERE nombre == '${array[0]}'"
        pkill -u "${array[0]}"
        userdel  "${array[0]}"
        write_log_file "[ SSH : ${array[0]}:${array[1]} ] expiro el dia ${fecha_actual}"
    done
}

check_for_expire_ovpn_acc(){
    for user in $(sqlite3 "$db" "SELECT nombre,exp_date FROM ovpn WHERE exp_date == '${fecha_actual}'"); do
        IFS='|' read -r -a array <<< "$user"
        sqlite3 "$db" "DELETE FROM ovpn WHERE nombre == '${array[0]}'"
        # luego tengo que eliminar el archivo de configuracion
        write_log_file "[ OVPN : ${array[0]}:${array[1]} ] expiro el dia ${fecha_actual}"
    done

}

check_if_user_exceded_limit_max_conn(){
    for user in $(sqlite3 "$db" "SELECT nombre,password,max_conn FROM ssh"); do
        IFS='|' read -r -a array <<< "$user"
        local user_conn_openssh=$(ps auxwww | grep 'sshd:' | awk '{print $1 }' | grep -w -c "${array[0]}")
        
        process_is_running "dropbear" && {
            user_conn_dropbear=$(ps auxwww | grep 'dropbear' | awk '{print $1 }' | grep -w -c "${array[0]}")
            number_session=$((number_session_openssh + number_session_dropbear))
        } || {
            number_session=$user_conn_openssh
        }
        if (( $user_conn > ${array[2]} )) ; then
            write_log_file "${array[0]}:${array[1]} excedio el limite de conexiones ( ${array[2]} < ${user_conn} )"
            pkill -u "${array[0]}"
            userdel "${array[0]}"
            sqlite3 "$db" "DELETE FROM ssh WHERE nombre == '${array[0]}'"
        fi
    done
}


write_log_file(){
    local msg="$1"
    echo "[ $(date "+%Y-%m-%d %H:%M:%S") ] $msg" >> "$log_file"
}

view_log_file(){
    info "Mostrando archivo de registros."
    if [[ ! -f "$log_file" ]]; then error "El archivo ${GREEN}${log_file}${WHITE} no existe." ; exit 1 ; fi
    local lines=$(wc -l "$log_file" | awk '{print $1}')
    if (( $lines > 50 )); then cat "${log_file}" | less -R ; else cat "${log_file}" ; fi
    
}


check_exp_date_from_all_acc(){
    local used_ovpn=$(sqlite3 "$db" "SELECT count(*) FROM ovpn" &>/dev/null;echo $?)
    if [[ "${used_ovpn}" == 0 ]];then
        check_for_expire_ovpn_acc &
    fi
    check_for_expire_ssh
}

main(){
    local args="$1"
    case $args in
        "check_exp_date_from_all_acc"|1)
            check_exp_date_from_all_acc
            ;;
        "check_if_user_exceded_limit_max_conn"|2)
            check_if_user_exceded_limit_max_conn
            ;;
        "add_cron_job"|3)
            add_cront_job
            ;;
        "view_log"|4)
            view_log_file
            ;;
        "delete_temp_user"|5)
            delete_temp_user "${2}" "${3}"
            ;;
        "help"|"-h")
            help_msg
            ;;
    esac
}


help_msg(){
    info "Lista de argumentos validos:"
    echo -e "${WHITE}[ ${BLUE}1${WHITE} ]${GREEN} check_exp_date_from_all_acc ${WHITE}Comprueba si existen usuarios vencidos ( SSH Y OVPN )."
    echo -e "${WHITE}[ ${BLUE}2${WHITE} ]${GREEN} check_if_user_exceded_limit_max_conn ${WHITE}Comprueba si los usuarios superaron el limite de conexiones. ( SSH )"
    echo -e "${WHITE}[ ${BLUE}3${WHITE} ]${GREEN} add_cron_job ${WHITE}Agrega la tarea crontab para hitman."
    echo -e "${WHITE}[ ${BLUE}4${WHITE} ]${GREEN} view_log${WHITE} Ver el archivo de registros ( /var/log/FenixManager/hitman.log )."
    echo -e "${WHITE}[ ${BLUE}5${WHITE} ]${GREEN} delete_temp_user${WHITE} Elimina un usuario temporal ( Esta funcion tambien puede ser llamada para eliminar cualquier usuario. Es mejor evitarlo.)."
    info "Ejemplo: ${WHITE}hitman.bash ${GREEN}check_exp_date_from_acc_ssh${WHITE}"
    info "Ejemplo: ${WHITE}hitman.bash ${BLUE}1${WHITE}"
}

delete_temp_user(){
    local user="$1"
    local pass="$2"
    pkill -u "$user"
    userdel "$user"
    write_log_file "[ ${user}:${pass} ( temp ) ] expiro el dia ${fecha_actual}"

}
if [[ ! -z "${@}" ]]; then
    main "$@"
fi
