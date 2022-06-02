#!/bin/bash

# get terminal size
columns=$(tput cols) 

source "/etc/FenixManager/funciones/color.bash" 2>/dev/null
source "/etc/FenixManager/preferences.bash" 2>/dev/null

info(){ echo -e "\\033[1;33m[INFO]\\033[m \\033[1;37m$*\\033[m";}
error() { echo -e "\\033[1;31m[ERROR]\\033[m \\033[1;37m$*\\033[m";}
warning() { echo -e "\\033[1;33m[ADVERTENCIA]\\033[m \\033[1;37m$*\\033[m";}
space() { echo -e "\\033[1;34m〢────────────────────〢 \\033[m\\033[37m$*\\033[m\\033[1;34m 〢─────────────────── 〢\\033[m";}
separator() {
    local str=$@
    echo -e "\\033[1;34m〢────────────────────〢 \\033[m\\033[37m$*\\033[m\\033[1;34m 〢────────────────────────〢\\033[m";
}

delete_empty_lines(){
    local file=$1
    sed -i '/^$/d' "${file}"
}

line_separator() {    
    # ** $2 = color de la linea ( default: azul )
    # ** $1 = longitud de la linea
    local length_line color_
    str="〢"
    length_line=$1
    color_=$2
    [ -z $color_ ] && color_="${BLUE}"
    if [[ "$length_line" -lt 0 ]];then  length_line=50 ; fi
    for i in $(seq 1 $length_line);do  str+="─" ; done
    echo -e "${BLUE}${str}〢${WHITE}"
}
stty -echoctl # hide ^C
trap ctrl_c SIGINT SIGTERM

fenix() {
    "$script_dir/fenix-menu.bash"
}

check_and_veriy_preferences_integrity(){
    local file_restored=0
    # ! check integrity of preferences.bash
    local file="/etc/FenixManager/preferences.bash"
    local file_linenumber=$(wc -l ${file} 2> /dev/null| awk '{print $1}')
    if [ ! -f "$file" ] || [ "$file_linenumber" -eq "1" ];then
        error "El archivo de preferencias no existe o esta alterado."
        local user_=$(logname)
        [[ "${user}" == "root" ]] && local user_folder="/root" || local user_folder="/home/${user_}"
        grep "#dev" "/etc/FenixManager/version" &> /dev/null && {
            local branch_clone="dev"
            local version=$(cat "/etc/FenixManager/version" | cut -d "#" -f 1)
        } || {
            local branch_clone="master"
            local version=$(cat "/etc/FenixManager/version" )
        }
        local preferences_var=("show_fenix_banner=true" "user_folder='${user_folder}'" "script_dir='/etc/FenixManager'" "version='1.0'" "hide_first_panel='false'" "hide_second_panel='false'" "hide_third_panel='false'" "hide_fourth_panel='false'" "hide_ports_open_services_in_home_menu='false'" "hide_ports_open_services_in_protocol_menu='false'")
        for i in "${preferences_var[@]}"; do
            echo "$i" >> "$file"
        done
        ((file_restored++))
        info "Se creo el archivo de preferencias."
    fi
    # ! check integrity of color.bash
    local file_color="/etc/FenixManager/funciones/color.bash"
    local file_linenumber=$(wc -l ${file_color} 2> /dev/null| awk '{print $1}')
    if [ ! -f "${file}" ] || [ -z "${file_linenumber}" ] || [ "${file_linenumber}" -eq "1" ];then
        error "El archivo de color no existe o esta alterado."
        local color_content="IyEvdXNyL2Jpbi9iYXNoCgoKR1JFRU49IlxcMDMzWzMybSIKI1dISVRFPSJcXDAzM1szN20iCldISVRFPSJcXDAzM1sxOzM3bSIKRU5EX0NPTE9SPSJcXDAzM1ttIgpZRUxMT1c9IlxcMDMzWzMzbSIKTUFHRU5UQT0iXFwwMzNbMzVtIgpCTFVFPSJcXDAzM1szNG0iCkJCTFVFPSJcXDAzM1sxOzM0bSIKI1JFRD0iXFwwMzNbMzFtIgpSRUQ9IlxcMDMzWzE7MzFtIgpncmVlbj0iXFwwMzNbMzJtIgp3aGl0ZT0iXFwwMzNbMTszN20iCmVuZF9jb2xvcj0iXFwwMzNbbSIKeWVsbG93PSJcXDAzM1szM20iCm1hZ2VudGE9IlxcMDMzWzM1bSIKYmx1ZT0iXFwwMzNbMzRtIgpyZWQ9IlxcMDMzWzMxbSI="
        base64 -d <<< "${color_content}" > "${file_color}"
        info "Se creo el archivo de color."
        ((file_restored++))
    fi
    [ "${file_restored}" -gt "0" ] && {
        echo -e "Vuelva a ejecutar el script para continuar."
        read -p "Presione [Enter] para continuar..."
        exit 0
    }
}

ctrl_c() {
    exit 130
    echo ""
}

port_input() {
    # Una simple funcion para pedir un puerto y validarlo.
    # Los puertos validos,son almacenados en puertos_array.
    # Es importante, que despues de usar esta funcion, se ejecute el comando "unset puertos_array"
    puertos_array=()
    while true;do
        trap ctrl_c SIGINT SIGTERM
        read -r -p "$(echo -e "${WHITE}[*] Puertos a agregar : ")" puertos
        IFS=' ' read -r -a puertos <<< "$puertos"
        for puerto in "${puertos[@]}";do
            [[ -z "${puerto}" ]] && continue 
            #if [[ ! $(grep -q "^[0-9]+$" <<< "$puerto") ]] ;then error "($puerto). No es un numero" ; continue ; fi
            if [[ ! $puerto =~ ^[0-9]+$ ]];then error "($puerto). No es un numero" ; fi
            if [[ $puerto -lt 1 ]] || [[ "$puerto" -gt 65535 ]] ;then error "El puerto ($puerto) no es valido." ; continue ; fi
            check_if_port_is_open "$puerto"
            if [[ $? -eq 1 ]];then
                continue
            else
                puertos_array+=("$puerto")
                package_installed "ufw" && ufw allow $puerto/tcp &>/dev/null
            fi
        done
        if [[ ${#puertos_array[@]} -eq 0 ]];then  continue ; fi
        break
        done
}

script_executed_with_root_privileges() {
    if [ "$(id -u)" = "0" ]; then
        return 0
    else
        error "Este script debe ser ejecutado con privilegios de root"
        exit 1
    fi
}


check_if_port_is_open() {
    # 0 = port is open , 1 = port is closed
    port=$1
    pid_use_port=$(ss -lptn "sport = :$port" | awk '{split($6,a,":");print a[2]}' | tr -d '\n')
    port_tmp=""

    if [ -z "$pid_use_port" ];then
        return 0
    else
        error "El puerto $port está siendo usado por el proceso ${pid_use_port}"
        return 1
    fi  
}


print_banner () {
    banner="[1;31m
             _/|       |\_
            /  |       |  \ 
           |    \     /    |
           |  \ /     \ /  |
           | \  |     |  / |
           | \ _\_/^\_/_ / |
           |    --\//--    |
            \_  \     /  _/
              \__  |  __/
                 \ _ /
                _/   \_[m [33m    Mathiue 1001[m
              [1;31m / _/|\_ \ [m [33m  Fenix Manager[m
               [1;31m /  |  \   [33m  Version: ${GREEN}${version}[m
                [1;31m / v \ 
"
    echo -e "$banner"
}

option_color () {
    option="${1}"
    string="${2}"
    if [[ "$option" == "E" ]];then
        # ! EXIT OPTION
        printf "${WHITE} [ ${RED}${option}${WHITE} ]${YELLOW} >> ${WHITE}${RED}$string\n"
    else
        if [[ "$option" == [mM] ]];then
            # ! MENU PRINCIPAL
            printf "${WHITE} [ ${YELLOW}$option${WHITE} ]${YELLOW} >> ${YELLOW}$string${WHITE}\n"
        elif [[ "$option" == [bBk] ]];then
             # ! REGRESAR
            printf "${WHITE} [ ${BLUE}$option${WHITE} ]${YELLOW} >> ${BLUE}$string${WHITE}\n"
        else
            if [[ "$string" == *"DESINSTALAR"* ]];then
                local str_2="${RED}$string"
            else
                local str_2="${WHITE}$string"
            fi
            printf "${WHITE} [ ${GREEN}$option${WHITE} ]${YELLOW} >> ${str_2}\n"
        fi
    fi
}

option_menu_package(){
    # $2 = lista de paquetes
    local GREEN=$(tput setaf 2)
    local RED=$(tput setaf 1)
    local WHITE=$(tput setaf 7)
    local YELLOW=$(tput setaf 3)

    array_of_packages=("$@")
    option=0

    installed_packages=()
    if [[ -z "${array_of_packages}" ]] ;then error "Faltan parametros" ; return 1 ; fi
    
    # ! 62
    for i in "${array_of_packages[@]}";do
        ((option++))
        
        [[ "${i}" =~ "OPENSSH / DROPBEAR" ]] && {
            local str_="${WHITE}[ ${GREEN}INSTALADO ${WHITE}/"
            
            package_installed "dropbear" && {
                local str_+="${GREEN} INSTALADO ${WHITE}]"
                installed_packages+=("dropbear")
            
            } || local str_+="${RED} NO INSTALADO${WHITE}]"
        
        } || {
            if ! package_installed "$i";then
                local str_="${WHITE}[${RED} NO INSTALADO ${WHITE}]"
            else
                installed_packages+=($i)
                # ! tmp_array=( "squid" "stunnel4" "slowdns" "shadowsocks-libev" "openvpn" "v2ray" "python3-proxy")
                # check if package is active

                # ! SLOWDNS
                if [[ "${i}" == "slowdns" ]];then
                    pgrep -f "slowdns" &>/dev/null && {
                        local activo=0
                        }  || local activo=1
                # ! BADVPN-UDPGW
                elif [[ "${i}" == "badvpn-udpgw" ]];then
                    pgrep -f "badvpn-udpgw" &>/dev/null && {
                        local activo=0
                        }  || local activo=1
                # ! SHADOWSOCKS-LIBEV
                elif [[ "${i}" == "shadowsocks-libev" ]];then
                    pgrep obfs-server &>/dev/null && local activo=0 || {
                        pgrep ss-server &>/dev/null && local activo=0 || local activo=1
                    }
                else
                    systemctl is-active "${i//"openvpn"/"openvpn@server"}" &>/dev/null && {
                        local activo=0
                        } || {
                        local activo=1
                    }
                fi
                [[ ${activo} -eq 0 ]] && local str_="${WHITE}[ ${GREEN}ACTIVO ${WHITE}]" || local str_="${WHITE}[${RED} INACTIVO ${WHITE}]"
            fi
        }
        local str_rel="-"
        local length=$(( 65 - ${#i} - ${#str_} ))
        local length=${length//-/ } # negative number
        for ((j=0;j<length;j++));do
            str_rel+="-"
        done
        printf "${WHITE} [ ${GREEN}${option}${WHITE} ]${YELLOW} >>${WHITE} ${i^^} ${str_rel} ${str_}${WHITE}\n"
        
    done

}

check_user_exist () {
    user=$1
    mysql_db='/etc/FenixManager/database/usuarios.db'
    
    sqlite3 $mysql_db "SELECT * FROM ssh WHERE nombre='$user'" | grep -c "$user" &> /dev/null
    user_exists_unix=$(getent passwd "$user" &>/dev/null)

    if [ $? != 0 ] || [[ $user_exists_unix == 0 ]]; then
        return 0
    else
        error "El usuario $user ya existe"
        return 1
    fi
}

bar() {
    help_msg() {
        error "Parametros desconocidos."
        info "$0 --cmd <comando> --title <texto> --show-eta <true|false>"
        info "$0 <comando>"
        #
        info "Al parametro --cmd y --title , se le pasan los argumentos codificado en base64."
        exit 1
    }
    while [[ $# -gt 0 ]]; do
        [[ ! "$1" =~ ^-- ]] && {
            local cmd_="$@"
            shift ; break
        }
        case $1 in 
            "--cmd")
                local cmd_="${2}"
                shift ; shift
                ;;
            "--title")
                local title="${2}"
                shift ; shift
                ;;
            "--show-eta")
                local show_eta_="${2}"
                shift ; shift
                ;;
            *|"--help")
                help_msg
                ;;
            
        esac
    done
    [[ -z "${cmd_}" ]] && help_msg
    [ -z "${title}" ] && local title="${cmd_}"
    [ -z "${show_eta_+x}" ] && local show_eta_="true"
    local str="###############"
    local s=0.25
    local tmpfile=$(mktemp -t progress.XXXXXXXX)
    
    # colors var
    local green='\033[32m'
    local red='\033[31m'
    local yellow='\033[33m'
    local end='\033[0m'
    
    blc_=0
 
    while [[ $blc -eq 0 ]];do 
        for i in {1..14}; do
            sleep 0.25
            s=$(echo ${s} + 0.25| bc)
            [[ "${show_eta_}" == "true" ]] && {
                printf "\33[2K\r[ $yellow%s$end ] $green [%-16s $end%s" "$title" "${str:0:$i}]" " ET: ${s}s"  | tee "$tmpfile" # save time 
            } || {
                printf "\33[2K\r[ $yellow%s$end ] $green [%-16s $end%s" "$title" "${str:0:$i}]"  # save time 
            }
            done
        done  & 
    
    trap "blc_=1" SIGINT SIGTERM 
    ${cmd_} &> /dev/null || STAT=$? && true
    trap '"(kill -9 $!)"' SIGINT SIGTERM 
    kill $! &> /dev/null
    local endtime=$(awk '{split($0,a,"ET:");print a[2] }' < "$tmpfile" )

    
    # Depende el comando ejecutado,devuelve ok,instalado o error.
    if [[ $STAT -eq 0 ]];then
        local result='OK'
        local result_color=$green #green
        if [[ "${cmd_}" == "*install*" ]] ;then
            local result='INSALADO'
            local result_color=$green # green 
        fi
    else
        local result='FALLO !'${STAT}
        local result_color=$red #red
    fi

    [[ ! "${show_eta_}" == "true" ]] && {
        printf "\33[2K\r[ $yellow%s$end ] $result_color [%-15s]$end [$result_color%s$end] %s \n" "$title" "${str}" "${result}" 
    } || {
        printf "\33[2K\r[ $yellow%s$end ] $result_color [%-15s]$end [$result_color%s$end] %s \n" "$title" "${str}" "${result}" " ET: ${endtime}"
    }
    rm -f "${tmpfile}"
    return $STAT

}


package_installed () {
    # 1 = not installed, 0 = installed
    package=$1
    cmd=$(dpkg-query -W --showformat='${Status}\n' "$package" 2>/dev/null| grep -c "install ok installed" && return 0 || return 1)
    
    if [[ "$package" == "v2ray" ]];then if [[ -f "/usr/local/bin/v2ray" ]];then cmd=1 ; else cmd=0 ; fi ; fi
    if [[ "$package" == "fenixmanager-pysocks" ]];then if [[ -f "/etc/systemd/system/fenixmanager-pysocks.service" ]];then cmd=1 ; else cmd=0 ; fi ; fi
    if [[ "$package" == "slowdns" ]];then if [[ -f "/etc/FenixManager/bin/slowdns" ]];then cmd=1 ; else cmd=0 ; fi ; fi
    if [[ "$package" == "badvpn-udpgw" ]];then which badvpn-udpgw &> /dev/null && cmd=1 || cmd=0 ; fi
    if [[ $cmd == 1 ]]; then
        return 0
    else
        return 1

    fi
}

get_all_ip_from_adapters() {
    IPS_LISTS=()
    public_ip=$(curl ipinfo.io/ip -s)
    cmd=$(ip addr | grep 'inet ' | awk '{print $2}' | awk -F '/' '{print $1}')
    if [[ $? != 0 ]]; then error "No se pudo obtener las IPs de los adaptadores" ; return 1
    else
        IPS_LISTS=("$cmd")
    fi
    IPS_LISTS+=("$public_ip")
}

redirect_to_service() {
    # ! La variable global 'SERVICE_REDIRECT',contiene el puerto del servicio seleccionado.
    # Despues listar los puertos disponibles por pysocks
    local hidden_service="$1"
    local service_available=("ssh" "dropbear" "openvpn" "pysocks")
    [[ "${hidden_service}" == "pysocks" ]] && service_available=(${service_available[@]/'pysocks'})
    
    openvpn_ports=$(grep -oP '^\s*port\s+\K[0-9]+' /etc/openvpn/server.conf 2>/dev/null &)
    # check service is running
    line_separator 62
    printf "${WHITE}〢[ %-2s]| %-12s| %-31s| %-8s〢\n" "#" "Servicio" "Puerto" "Estado"
    local count=0
    local array_service=()
    for service in "${service_available[@]}"; do
        (( count++ ))
        if [[ $service == "openvpn" ]]; then
            service openvpn@server status &>/dev/null
        elif [[ $service =~ "pysocks" ]]; then
            systemctl is-active fenixmanager-pysocks &>/dev/null
        else
            pgrep "$service" &> /dev/null
        fi

        if [[ $? == 0 ]]; then
            if [[ "$service" == "openvpn" ]];then
                ports_used_by_service=$openvpn_ports
            elif [[ "${service}" == "pysocks" ]];then
                local pysocks_conf_fil="${user_folder}/FenixManager/py-socks.conf"
                ports_used_by_service=$(grep "^accept=.*" "${pysocks_conf_fil}" | awk '{split($0,a,"=");print a[2]}' | tr "\n" " ")
            else
                ports_used_by_service=$(netstat -ltnp | grep "$service" | awk '{split($4,a,":"); print a[2]}' | tr '\n' ' ')
            fi
            printf "〢${green}[ %-2s]${WHITE}| ${green}%-12s${WHITE}| ${green}%-31s${WHITE}| ${green}%-8s${WHITE}〢\n" "$count" "$service" "$ports_used_by_service" "ACTIVO"
            array_service+=("$count:$ports_used_by_service")

        else
            (( count-- ))
            printf "〢${red}[ %-2s]${WHITE}| ${red}%-12s${WHITE}| ${red}%-31s${WHITE}| ${red}%-8s${WHITE}〢\n" "-" "$service" "-" "INACTIVO"
        fi
    done
    line_separator 62
    printf "${WHITE}〢${YELLOW}[ %-2s ]${WHITE} %-30s %25s\n" "10" "UTILIZAR UN PUERTO PERSONALIZADO" "〢"
    line_separator 62
    while true;do
        read  -r -p "$(echo -e "${WHITE}[*] # del servicio al que desea redireccionar: ")" service_number
        if [[ -z "$service_number" ]]; then continue ; fi
        if grep -E "[a-z]|[A-Z]" <<< "$service_number" &>/dev/null;then continue ; fi
        if [[ $service_number -lt 1 ]] || [[ $service_number -gt 10 ]]; then continue ; fi
        local port_number
        local port_list=(${array_service[$service_number-1]})
        local port_number="$(awk -F ":" '{print $2}' <<< "${port_list[0]}" )"
        break
        
    done
    
    if [[ $service_number == 10 ]]; then
        until [[ $port_number =~ ^[0-9]+$ ]]; do
            read -r -p "$(echo -e "${yellow}[*] Ingrese el  puerto: ")" port_number
            if [[ -z "$port_number" ]]; then continue ; fi
        done
    fi

    export SERVICE_REDIRECT=${port_number:-$service_number}

}

list_certs() {
    cert_dir="${user_folder}/FenixManager/cert-ssl/"
    info "Directorios de certificados SSL : ${GREEN}${cert_dir//"${user_folder}"/"~"}${WHITE}"
    local certs=$(ls ${user_folder}/FenixManager/cert-ssl/)
    local count_=0
    
    if [[ -z "$certs" ]] ;then error "No hay certificados." ; return 1 ;fi
    line_separator 60
    printf "〢 ${blue}%-2s ${green}%-30s ${yellow}%-25s${WHITE}〢\n" '#' 'Nombre' 'Fecha de creacion' 
    line_separator 60

    for i in $certs;do
        (( count_ ++ ))
        certs_array+=("$i")
        [[ "${i}" =~ ".pem"|".crt"|".cert" ]] && local color_="${GREEN}" || local color_="${RED}"

        date_=$(date -r "$cert_dir$i" +"%d/%m/%Y")
        local length_=$(echo 60 - ${#count_} - 30 - ${#date_} | bc)
        printf "〢 ${blue}%-2s ${color_}%-40s ${yellow}%-15s${WHITE}〢\n" "$count_" "$i" "$date_"
    done
    line_separator 60
    
    while true;do
        read -r -p "$(echo -e "${green}[*] Certificado (*.cert,*.pem,*.crt): ")" cert_opt
        if [[ -z "$cert_opt" ]] || [[ $cert_opt -gt $count_ ]] || grep -E "[a-z]|[A-Z]" <<< "$cert_opt" &>/dev/null;then
            continue
        else
            CERT_FILE=$cert_dir${certs_array[$cert_opt-1]}
            break
        fi
    done
    [[ ! $CERT_FILE =~ "pem" ]] && {
        while true;do
            read -r -p "$(echo -e "${RED}[*] Llave privada (*.key): ")" key_file
            if [[ -z "${key_file}" ]] || [[ "${key_file}" -gt $count_ ]] || [[ "${key_file}" =~ "[a-z]|[A-Z" ]];then continue ; fi
            export KEY_FILE="$cert_dir${certs_array[$key_file-1]}" &>/dev/null
            break
        done
    } || export KEY_FILE="$CERT_FILE" 

}

cert_gen() {
    info 'Generando un certificado ssl autofirmado.'
    cert_dir="${user_folder}/FenixManager/cert-ssl/"
    
    read -r -p "$(echo -e "${WHITE}[*] Ingrese el dominio del certificado (fenixmanager.com): ")" domain
    if [[ -z "$domain" ]];then  domain='fenixmanager.com' ; fi
    
    if [[ ! -d "${cert_dir}" ]];then mkdir -p "${cert_dir}" ; fi

    regex_domain='(?=^.{4,253}$)(^(?:[a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,}|xn--[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$)' 
    grep -P "$regex_domain" <<< $domain &> /dev/null
    if [[ $? != 0 ]];then
        error "El dominio no es valido."
        info 'Por omision,se usara "fenixmanager.com"'
        domain='fenixmanager.com'
    fi

    name="$cert_dir$domain-autogen_"
    
    openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -x509 -days 365 -out "$name.crt" -subj "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=$domain" &>/dev/null
    if [[ $? != 0 ]];then
        error "No se pudo generar el certificado."
        return 1
    else
        cat "$name.crt" >> "$name.pem"
        cat "$name.key" >> "$name.pem"
        
        CERT_FILE="$name.pem"
        rm "$name.crt" "$name.key" &>/dev/null
        info "Certificado guardado en : $cert_dir"
    fi
}

stunnel4_whats_cert_to_use(){
    echo -e "${GREEN}\n[*] Que certificado ssl desea utilizar:\n${WHITE}[ ${BLUE}1 ${WHITE}] Certificado autogenerado por el script.\n${WHITE}[ ${BLUE}2 ${WHITE}] Cargar un certificado\n${WHITE}"
    
    while true;do
        trap ctrl_c SIGINT SIGTERM SIGKILL
        read -p "$(echo -e "$BLUE[*] Ingrese la opcion ${endcolor}") : " option
        case  $option in
            1 )
                cert_gen
                break
                ;;
            2 )
                list_certs
                if [[ $? == 1  ]];then info 'Descargue y guarde su certificado,o genere uno con la opcion 1.' ; continue ; fi
                break
                ;;
            q | Q | e | E )
                exit 0
                ;;
            M | m )
                fenix
                ;;
            esac
    done
}
mk_backup() {
    local file="$1"
    local name_backup=$2
    if [[ -z "$name_backup" ]];then name_backup="$file.bak"; fi
    cp "$file" "$name_backup"
    if [[ $? != 0 ]];then
        error "No se pudo crear el backup."
        return 1
    fi
}
    
rm_init_cfg_and_end_cfg_from_file() {
    # Buscara en $file el string que comienze con : #$package-init-config y apartir de ahi borrara hasta el siguiente : #$package-end-config
    local file="$1"
    local package="$2"
    local string_init="#$package-init-config"
    local string_end="#$package-end-config"

    local init_line_number, end_line_number
    init_line_number=$(grep -n "${string_init}" "$file" | cut -d ":" -f 1)
    end_line_number=$(grep -n "${string_end}" "$file" | cut -d ":" -f 1)
    
    sed -i "${init_line_number},${end_line_number}d" "$file"
    if [[ $? != 0 ]];then error "No se pudo borrar el archivo."  ; return 1 ; fi
}


process_is_running(){
    # 0 = process is running 
    # 1 = process is not running
    process="$1"
    if [[ $(ps -ef | grep "$process" | grep -v grep | wc -l) -gt 0 ]];then return 1 ; else return 0 ; fi
}

list_banners(){
    # LISTA TODO LOS BANNERS EN EL DIRECTORIO
    # LA OPCION ELEGIDA POR EL USUARIO SE GUARDA EN LA VARIABLE BANNER_FILE
    local banners_dir="${user_folder}/FenixManager/banner/"
    info "Directorio de banners: ${GREEN}${banners_dir//"${user_folder}"/"~"}${WHITE}"
    local banners_array=($(ls "${banners_dir}/"))
    line_separator 60
    printf "${WHITE}〢 ${GREEN}%-4s ${YELLOW}%-25s ${WHITE}%-10s %13s\n" "ID" "NOMBRE" "FECHA DE CREACION" "〢"
    line_separator 60
        
    for (( i=0; i<(${#banners_array[*]}); i++ ));do
        local file="${banners_array[$i]}"
        local fullpath_file="${banners_dir}${file}"
        local file_size="$(du -sh ${fullpath_file} | cut -f1)"
        local file_date=$(stat -c %y "${fullpath_file}" | cut -d " " -f 1)
        local lenght_date=${#file_date}
        printf "${WHITE}〢 ${GREEN}%-4s ${YELLOW}%-25s ${WHITE}%-10s %$((60 - 5 - 25 -10))s\n" "$i" "$file"  "$file_date" "〢"
    done 
    line_separator 60
    while true;do
        read -r -p "$(echo -e "${WHITE}[*] ID del banner : ")" banner_id
        if [[ $banner_id -lt 0 || $banner_id -gt ${#banners_array[@]}-1 ]];then
            error "El ID ingresado no es valido."
            continue
        else
            break
        fi
    done
    BANNER_FILE="${banners_dir}${banners_array[$banner_id]}"
}


list_services_and_ports_used(){ # ! GET PORT FROM SERVICES
    local get_actived_services="$1"
    services_actived=()
    local list_services=(sshd dropbear stunnel4 squid pysocks openvpn x-ui udpgw shadowsocks-libev)
    [[ "${get_actived_services}" == "get_actived_services" ]] && {
        list_services+=("v2ray")
    }
    local c=0    
    
    for services_ in "${list_services[@]}";do
        if [[ "${services_}" == "pysocks" ]];then
            systemctl status "fenixmanager-pysocks" &>/dev/null
        elif [[ "${services_}" == "openvpn" ]];then
            systemctl status "openvpn@server" &>/dev/null
        elif [[ "${services_}" == "udpgw" ]];then
            pgrep badvpn-udpgw &> /dev/null
        elif [[ "${services_}" == "shadowsocks-libev" ]];then
            pgrep obfs-server &> /dev/null || {
                pgrep ss-server &>/dev/null
            }
        else
            systemctl status "${services_}" &>/dev/null
            
        fi

        [[ $? -eq  0 ]] && {
            local color_="${GREEN}"
            local status_="[ ACTIVO ]"
        } || {
            local color_="${RED}"
            local status_="[ INACTIVO ]"
        }
        case $services_ in
            "sshd")
                local port_listen=$(cat /etc/ssh/sshd_config | grep -o "^Port .*" | awk '{split($0,a," "); print a[2]}' | xargs)
                ;;
            "dropbear")
                local file="/etc/default/dropbear"
                local dropbear_port=$(cat "$file" 2>/dev/null | grep -o "DROPBEAR_PORT=.*" | awk '{split($0,a,"="); print a[2]}')
                local dropbear_extra_arg_port=$(cat "$file" 2>/dev/null | grep -o "DROPBEAR_EXTRA_ARGS=.*" | awk '{split($0,a,"-p"); print a[2]}'| tr "'" " " | xargs)
                [[ -n "${dropbear_port}" ||  -n "${dropbear_extra_arg_port}" ]] && {
                    local port_listen="$dropbear_port ${dropbear_extra_arg_port//''/ }"
                } || local port_listen=""
                ;;
            "stunnel4")
                local port_listen=$(cat /etc/stunnel/stunnel.conf 2>/dev/null | grep "^accept .*" | awk '{split($0,a,"="); print a[2]}' | xargs)
                ;;
            "squid")
                local port_listen=$(cat /etc/squid/squid.conf 2>/dev/null | grep -o "^http_port .*" | awk '{split($0,a," "); print a[2]}' | xargs)
                ;;
            "pysocks")
                local port_listen=$(cat ${user_folder}/FenixManager/py-socks.conf 2>/dev/null | grep "^accept=.*" | awk '{split($0,a,"=");print a[2]}' | xargs)
                ;;
            "shadowsocks-libev")
                pidof obfs-server &>/dev/null && services_+=" obfs"
                local port_listen=$(cat /etc/shadowsocks-libev/config.json 2>/dev/null | grep "\"server_port\": .*" | awk '{split($0,a,":"); print a[2]}' | sed 's/"/ /g; s/,/ /g' | xargs )
                ;;
            "openvpn")
                #local is_running=$(service openvpn@server status &>/dev/null;echo $?)
                local port_listen=$(cat /etc/openvpn/server.conf 2>/dev/null  | grep -E 'port [0-9]{0,}' | grep -Eo '[0-9]{4,5}' | xargs)
                ;;
            "v2ray")
                local is_running=$(service v2ray status &>/dev/null;echo $?)
                [[ "${is_running}" == 0 ]] && local port_listen="configurar puertos desde x-ui"  || local port_listen="" 
                ;;
            "x-ui")
                local port_listen=$(service x-ui status 2>/dev/null | grep -Eo "\[\::\]:.*" | awk '{split($0,a,":"); print a[4]}' | xargs 2>/dev/null)
                ;;
            "udpgw")
                local badvpn_pids=$(pgrep badvpn-udpgw)
                local port_listen
                for i in $badvpn_pids;do
                    local port_listen+="$(cat "/proc/${i}/cmdline" | sed -e "s/\x00/ /g" | grep -oE ":[0-9]{0,9}" | tr ":" " " | xargs) "
                done
                ;;
        esac
        if [[ -n "${port_listen}" ]];then
            [[ "${get_actived_services}" == "get_actived_services" ]] && {
                services_actived+=("${services_}")
            } || {
                printf "${WHITE}〢 ${color_}%-${#services_}s${WHITE}: ${YELLOW}%-10s ${WHITE}%$((62 - ${#services_} - 13))s\n" "${services_^^}" "${port_listen}"  "〢"
            }
        fi
    done
}


add_cron_job_for_hitman(){
    local fenixmanager_crontab="/etc/cron.d/fenixmanager"
    info "Agregando tarea crontab para ${GREEN}hitman${WHITE}."
    info "Se crea el archivo ${GREEN}${fenixmanager_crontab}."
    echo "#!/bin/bash" > "${fenixmanager_crontab}"
    info "Se agrega la tarea crontab para ${GREEN}hitman${WHITE}."
    local str_cront="@daily root $script_dir/funciones/hitman.bash 1"
    local str_cront+="\n*/15 * * * * root $script_dir/funciones/hitman.bash 2 "
    echo -e "$str_cront" >> "${fenixmanager_crontab}"
    info "Los usuarios vencidos se eliminan a las ${YELLOW}00:00${WHITE} ( Hora local )."
    info "Cada ${YELLOW}15 minutos${WHITE}, hitman comprobara si los usuarios superaron el maximo de conexiones permitidas, si es asi, se ${RED}eliminaran.${WHITE}"
}


show_users_and_port_template(){
    local user_data usuario passwd exp_date max_conn
    local head_banner="╔══════════════════║${RED}FENIX-MANAGER-V1.0${WHITE}║══════║${RED}@M1001-BYTE${WHITE}║════════════════╗"
    
    local user_data=("${@}")
    local usuario="${user_data[0]}"
    local passwd="${user_data[1]}"
    local exp_date="${user_data[2]}"
    local max_conn="${user_data[3]}"
    
    echo -e "${head_banner}"
    
    printf " ${WHITE} USUARIO: ${YELLOW}%-${#usuario}s ${WHITE}\n" "${usuario^^}"
    printf " ${WHITE} CONTRASEÑA: ${YELLOW}%-${#passwd}s ${WHITE}\n" "${passwd^^}" 
    printf " ${WHITE} EXPIRACION: ${YELLOW}%-${#exp_date}s ${WHITE}\n" "${exp_date^^}" 
    printf " ${WHITE} CONEXIONES SIMULTANEAS: ${YELLOW}%-${#max_conn}s ${WHITE}\n" "${max_conn^^}" 
    [[ ! -z "${domain_}" ]] && {
        printf " ${WHITE} DOMINIO: ${YELLOW}%-${#domain_}s ${WHITE}%$(echo 74 - ${#domain_} - 9 | bc)s ${WHITE}\n" "${domain_^^}" 
    }
    local public_ip=$(cat /etc/FenixManager/ip 2>/dev/null || curl -s https://api.ipify.org)
    printf " ${WHITE} IP PUBLICA: ${YELLOW}%-${#public_ip}s ${WHITE}%$(echo 74 - ${#public_ip} - 12 | bc)s ${WHITE}\n" "${public_ip^^}" 
    
    printf "╟%25s║${GREEN}%22s${WHITE}║%28s╢\n" "═" "~~~PUERTOS~ABIERTOS~~~" "═" | sed 's/ /═/g'
    list_services_and_ports_used
    printf "${WHITE}╚%73s╝\n" | sed 's/ /═/g'

}


uninstall_fenixmanager(){
    local fenix_rm=("/etc/FenixManager/" "/var/log/FenixManager/" "${user_folder}/FenixManager/" "/etc/cron.d/fenixmanager" "/usr/bin/fenix")
    local services_to_remove=("dropbear" "stunnel4" "squid" "openvpn" "shadowsocks-libev" "pysocks" "v2ray" "x-ui")
    clear
    echo -e "${BLUE}〢────────────〢 ${RED}DESINSTALANDO FENIX-MANAGER${BLUE} 〢───────────────〢"
    info "Los siguientes directorios/archivos seran eliminados:"
    for i in "${fenix_rm[@]}";do echo -e "${WHITE}${RED}  ${i}${WHITE}" ; done
    echo ""
    info "${RED}TODOS${WHITE} los usuarios ${YELLOW}SSH ${WHITE}/${WHITE} ${YELLOW}OPENVPN${WHITE} / ${YELLOW}V2RAY${WHITE} seran eliminados."
    info "El archivo ${RED}${user_folder}/.bashrc${WHITE} sera restaurado por el original (${GREEN}/etc/skel/.bashrc${WHITE})."
    info "Eliminara la entrada ${RED}/bin/false${WHITE} del archivo ${GREEN}/etc/shells${WHITE}."
    
    info "Los siguientes protocolos seran eliminados:"
    for service in "${services_to_remove[@]}";do echo -e "${WHITE}${RED}  ${service}${WHITE}" ; done
    read -rp "[*] Continuar con la desinstalacion ? [y/n]: " yes_no
    if [[ "${yes_no}" == [yYsS] ]];then
        # removed dir
        list_services_and_ports_used "get_actived_services" # return 'services_actived' with all services actived
        # removed protocol
        for service in "${services_to_remove[@]}";do
            if [[ "${services_actived[*]}" =~ "${service}" ]];then
                # ! FENIXMANAGER PYSOCKS
                if [[ "${service}" == "pysocks" ]];then
                    systemctl disable fenixmanager-pysocks
                    rm /etc/systemd/system/fenixmanager-pysocks.service &>/dev/null
                    systemctl daemon-reload
                    info "Eliminando  FenixManager-pysocks"
                # ! OPENVPN
                elif [[ "${service}" == "openvpn" ]];then
                    /etc/FenixManager/funciones/ovpn.bash
                    remove_openvpn "0"
                # ! X-UI
                elif [[ "${service}" == "x-ui" ]];then
                     yes | x-ui uninstall &>/dev/null
                     local x_ui_bin=$(which x-ui)
                     info "Eliminando  ${GREEN}${x_ui_bin}."
                     rm ${x_ui_bin} -f &>/dev/null
                # ! V2RAY 
                elif [[ "${service}" == "v2ray" ]];then
                    /etc/FenixManager/funciones/v2ray/v2ray-install-release.bash --remove
                else
                    bar --cmd "apt-get remove --purge ${service} -y" --title "Eliminando ${service}"
                fi
            fi
        done

        # * Delete all ssh accounts
        declare -f delete_all_users_ssh &>/dev/null && {
            yes | delete_all_users_ssh "1"
        }
        # * rmeove fenix directory
        cd /tmp &>/dev/null
        for i in "${fenix_rm[@]}";do
            rm -rf "${i}" && {
                info "Eliminado ${GREEN}${i}${WHITE}."
            }
        done
        # * remove badvpn-udpgw
        local badvpn_bin=$(which badvpn-udpgw)
        rm  "${badvpn_bin}" && {
            info "Eliminando ${GREEN}${badvpn_bin}${WHITE}."
        }

        # * remove stunnel4 dir
        rm /etc/{stunnel,stunnel4} -rf &>/dev/null
        # * delete /bin/false from /etc/shells
        grep -q "/bin/false" /etc/shells && {
            sed -i '/\/bin\/false/d' "/etc/shells"
            info "Eliminado ${RED}/bin/false${WHITE} del archivo ${GREEN}/etc/shells"
        }
        
        # * restore .bashrc
        info "Restaurando ${GREEN}${user_folder}/.bashrc"
        cp "/etc/skel/.bashrc" "${user_folder}/.bashrc"
        
        info "${RED}FENIX-MANAGER DESINSTALO CORRECTAMENTE."
        info "Por cualquier duda o sugerencias,podes contactarme por telegram:"
        info "${GREEN}@Mathiue1001 ${YELLOW} https://t.me/Mathiue1001"
        info "${GREEN}@M1001_byte ${YELLOW} https://t.me/M1001_byte"
        info "${GREEN}ScriptFenixManager ${YELLOW}https://t.me/ScriptFenixManager"
        info "Gracias por haber elegido ${YELLOW}FenixManager. :)"
        info "Su vps se reiniciará."
        read -rp "[*] Presione enter para continuar..."
        reboot
    else
        info "Cancelado por el usuario."
        exit 1
    fi
    
}

