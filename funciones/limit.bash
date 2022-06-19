#!/bin/bash

source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/ssh-user.bash"
source "/etc/FenixManager/funciones/color.bash"


db='/etc/FenixManager/databases/usuarios.db'
limiter_cfg_file="${user_folder}/FenixManager/limit_user.cfg"
if [ ! -f "$limiter_cfg_file" ]; then
    touch "$limiter_cfg_file"
fi

show_limit_info(){
    echo -e "${BLUE}〢───────────────〢 ${WHITE}LIMITADOR DE USUARIOS SSH ${BLUE}〢──────────────〢${WHITE}"
    cat "$limiter_cfg_file" | while read line;do
        [[ $line =~ ^\# || -z "$line"  ]] && continue
        IFS='|' read -ra array <<< "$line"
        printf "%b%s %b %-32s %b" "${WHITE}" "〢 Usuario: " "${GREEN}" "${array[0]}" "${WHITE}" 
        printf "%b%s %b %-8s%b" "${WHITE}" "CPU: " "${GREEN}" "${array[1]}%" "${WHITE}〢\n"
        done
    line_separator 60
}

activate_limiter(){
    local usuario="$1"
    local usage_cpu="${2//%/}"
    echo "${usuario}|${usage_cpu}" >> "${limiter_cfg_file}"
    local pid_user=$(ps auxwww | grep 'sshd:' | awk '{print $1,$2 }' | grep "${usuario}" | cut -d' ' -f2)
    local process_cpulimit=($(ps auxwww | grep 'cpulimit' | xargs))

    for i in $pid_user;do
        # ! check if i is presents in process_cpulimit
        if [[ ! "${process_cpulimit[*]}" =~ "${i}" ]];then
            info "Limitando usuario ${usuario}..."
            cpulimit -l "${usage_cpu}" -p "${i}" -b 2>/dev/null
        fi
    done
    
}

add_check_cron_job(){
    local fenixmanager_cronfile="/etc/cron.d/fenixmanager"

}

limit_user_main(){
    local opt="${1}"
    local percent_cpu_limit=(3 6 9 12 15 18)
    package_installed 'cpulimit' || {
        bar "apt-get install cpulimit"
    }
    list_id_user_simple
    while true;do
        read -ep "[*] Seleccione el usuario que desea limitar: " id_user
        [[ -z $id_user ]] && {
            echo -e "${rojo}[-] No has seleccionado ningun usuario${NC}"
            continue
        }
        local user_name=$(sqlite3 $userdb "select rowid,nombre from ssh where rowid = $id_user" 2>/dev/null| awk '{split($0,a,"|");print a[2]}')
        [[ -z $user_name ]] && {
            error "No existe un usuario con ese id. O no hay usuarios en la base de datos."
            continue
        }
        break
    done
    grep -q "${user_name}" "${limiter_cfg_file}" && {
        error "El usuario ${RED}${user_name^^}${WHITE} ya se encuentra limitado."
        return 1
    }
    for i in "${!percent_cpu_limit[@]}"; do echo -e "${WHITE}[ ${GREEN}${i}${WHITE} ]${WHITE} ${percent_cpu_limit[$i]} % ${WHITE}" ; done

    until [[ "${cpu_usage_percent}" =~ ^[0-9]+$ ]]; do
        read -ep "[*] Seleccione un porcentaje de uso de CPU: " cpu_usage_percent
    done
    local limit_="${percent_cpu_limit[${cpu_usage_percent}]}"

    echo -e "${verde}[+] Usuario seleccionado/s: ${GREEN}$([[ $user_name = "ALL" ]] && echo "TODOS" || echo "${user_name}")${WHITE}"
    echo -e "${verde}[+] Porcentaje de uso de CPU: ${GREEN}${limit_}${WHITE}"
    activate_limiter "$user_name" "$limit_"
}

remove_limiter_from_user(){
    info "Seleccione el usuario que desea eliminar del limitador."
    local user_in_file=($(cat ${limiter_cfg_file} | cut -d"|" -f1))
    for index in "${!user_in_file[@]}"; do
        echo -e "${WHITE}\t [ ${GREEN}${index}${WHITE} ]${WHITE} ${user_in_file[$index]}"
    done
    until [[ "${remove_user}" =~ ^[0-9]+$ ]]; do
        read -ep "[*] Seleccione id del usuario: " remove_user
    done
    local remove_user="${user_in_file[$remove_user]}"
    
    local pid_user=$(ps auxwww | grep 'sshd:' | awk '{print $1,$2 }' | grep "${remove_user}" | cut -d' ' -f2)
    local line_of_cfg=$(grep -o --line-number "${remove_user}" ${limiter_cfg_file} | cut -d: -f1)
    sed -i "${line_of_cfg}d" "${limiter_cfg_file}" 2>/dev/null
    sed -i '/^$/d' "${limiter_cfg_file}" 2>/dev/null # * remove empty lines
    
    for i in $pid_user;do
        kill -9 "${i}" 2>/dev/null
    done
    info "Usuario ${RED}${remove_user^^}${WHITE} eliminado del limitador."
}
limit_user_menu(){
    clear
    show_limit_info
    option_color "1" "LIMITAR USUARIO"
    option_color "2" "DESLIMITAR USUARIO"
    option_color "M" "MENU PRINCIPAL"
    option_color "E" "SALIR"
    while true;do
        prompt=$(date "+%x %X")
        read -r -p "$(printf "\33[2K\r${WHITE}[$BBLUE${prompt}${WHITE}] : ")" opt
        case $opt in
            1 ) limit_user_main ;;
            2 ) remove_limiter_from_user ;;
            "cls"|"cls") clear && limit_user_menu ;;
            [mM]) fenix ;;
            q|Q|e|E) exit 0 ;;
            *) tput cuu1 && tput el1 ;;
        esac
    done
}