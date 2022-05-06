#!/usr/bin/bash

# get terminal size
columns=$(tput cols) 

source "/etc/FenixManager/funciones/color.bash"
source "/etc/FenixManager/preferences.bash"

info(){ echo -e "\\033[1;33m[INFO]\\033[m \\033[1;37m$*\\033[m";}
error() { echo -e "\\033[1;31m[ERROR]\\033[m \\033[1;37m$*\\033[m";}
warning() { echo -e "\\033[1;33m[ADVERTENCIA]\\033[m \\033[1;37m$*\\033[m";}
space() { echo -e "\\033[1;34m〢────────────────────〢 \\033[m\\033[37m$*\\033[m\\033[1;34m 〢─────────────────── 〢\\033[m";}
separator() { echo -e "\\033[1;34m〢────────────────────〢 \\033[m\\033[37m$*\\033[m\\033[1;34m 〢─────────────────── 〢\\033[m";}
line_separator() {    
    # ** $2 = color de la linea ( default: azul )
    # ** $1 = longitud de la linea
    # ** Antes de invocar esta funcion y pasarle el parametro, hay que tener en cuentas dos cosas:
    # ** 1 - La longitud total de la linea,le tienes que restar dos (  El primer y ultimo caracter a agregar es el 〢 )
    # ** Ejemplo:
    # ** Si desea una linea de longitud de 20 caracteres, entonces debe pasarle 18
    local length_line color_
    [[ $columns -le 78 ]] && str="〢" || str="〢 "
    length_line=$1
    color_=$2
    [ -z $color_ ] && color_="${BLUE}"
    if [[ $length_line -lt 0 ]];then  length_line=50 ; fi
    for i in $(seq 1 $length_line);do  str+="─" ; done
    [[ $columns -le 78 ]] && {
        echo -e "${BLUE}${str}〢${WHITE}"
    } || {
        echo -e "${BLUE}${str} 〢${WHITE}"
    }
}
cfg_menu(){ echo -e "\\033[1;34m〢────────────────────〢 \\033[m\\033[37m$*\\033[m\\033[1;34m 〢─────────────────── 〢\\033[m";}
stty -echoctl # hide ^C
trap ctrl_c SIGINT SIGTERM

fenix() {
    "$script_dir/fenix-menu.bash"
}

check_and_veriy_preferences_integrity(){
    local file="/etc/FenixManager/preferences.bash"
    local file_linenumber=$(wc -l ${file} | awk '{print $1}')
    if [ ! -f "$file" ] || [ "$file_linenumber" -eq "1" ];then
        error "El archivo de preferencias no existe o esta alterado."
        local user_=$(logname)
        [[ "${user}" == "root" ]] && local user_folder="/root" || local user_folder="/home/${user_}"
        grep "#dev" "/etc/FenixManager/preferences.bash" &> /dev/null && {
            local branch_clone="dev"
            local version=$(cat "/etc/FenixManager/preferences.bash" | cut -d "#" -f 1)
        } || {
            local branch_clone="master"
            local version=$(cat "/etc/FenixManager/preferences.bash" )
        }
        local preferences_var=("user_folder='${user_folder}'" "script_dir='/etc/FenixManager'" "version='1.0'" "hide_first_panel='false'" "hide_second_panel='false'" "hide_third_panel='false'" "hide_fourth_panel='false'" "hide_ports_open_services_in_home_menu='false'" "hide_ports_open_services_in_protocol_menu='false'")
        for i in "${preferences_var[@]}"; do
            echo "$i" >> "$file"
        done
        info "Se creo el archivo de preferencias."
    fi

}

ctrl_c() {
    # Esto solo es valido para "software"/"programas" que no tienen un demonio habilitado en systemd.
    exit
}

port_input() {
    # Una simple funcion para pedir un puerto y validarlo.
    # Los puertos validos,son almacenados en puertos_array.
    # Es importante, que despues de usar esta funcion, se ejecute el comando "unset puertos_array"
    puertos_array=()
    while true;do
        trap ctrl_c SIGINT SIGTERM
        read -r -p "$(echo -e "${WHITE}[*] Puertos a agregar (separados por espacios) : ")" puertos
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
    array_of_packages=("$@")
    option=0

    installed_packages=()
    if [[ -z "${array_of_packages}" ]] ;then error "Faltan parametros" ; return 1 ; fi
    
    for i in "${array_of_packages[@]}";do
        ((option++))
        if ! package_installed "$i";then
            option_color "$option" "INSTALAR ${i^^}"
        else
            # ! tmp_array=( "squid" "stunnel4" "slowdns" "shadowsocks-libev" "openvpn" "v2ray" "python3-proxy")
            option_color "$option" "CONFIGURAR ${i^^}"
            installed_packages+=($i)
        fi
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
    # $1 es el texto que se muestra en la barra de progreso.Por defecto es el comando completo
    # $2 el comando a ejecutar
    local str="###############"
    local s=0.25
    local bg_process="$1"
    local textshow="$1"
    local tmpfile
    tmpfile=$(mktemp -t progress.XXXXXXXX)
    
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
            printf "\33[2K\r[ $yellow%s$end ] $green [%-16s $end%s" "$textshow" "${str:0:$i}]" " ET: ${s}s"  | tee "$tmpfile" # save time 
            done
        done  & 
    trap "blc_=1" SIGINT SIGTERM 
    ${bg_process} &> /dev/null || STAT=$? && true
    trap '"(kill -9 $!)"' SIGINT SIGTERM 
    kill $! &> /dev/null
    local endtime
    endtime=$(awk '{split($0,a,"ET:");print a[2] }' < "$tmpfile" )

    
    # Depende el comando ejecutado,devuelve ok,instalado o error.
    if [[ $STAT -eq 0 ]];then
        local result='OK'
        local result_color=$green #green
        if [[ $bg_process == "*install*" ]] ;then
        local result='INSALADO'
        local result_color=$green # green 
        fi
    else
        local result='FALLO !'${STAT}
        local result_color=$red #red
    fi

    printf "\33[2K\r[ $yellow%s$end ] $result_color [%-15s]$end [$result_color%s$end] %s \n" "$textshow" "${str}" "${result}" " ET: ${endtime}"
    rm -f "${tmpfile}"
    return $STAT

}

package_installed () {
    # 1 = not installed, 0 = installed
    package=$1
    cmd=$(dpkg-query -W --showformat='${Status}\n' "$package" 2>/dev/null| grep -c "install ok installed" && return 0 || return 1)
    
    if [[ "$package" == "v2ray" ]];then if [[ -f "/usr/local/bin/v2ray" ]];then cmd=1 ; else cmd=0 ; fi ; fi
    if [[ "$package" == "python3-proxy" ]];then if [[ -f "/etc/systemd/system/fenixmanager-pysocks.service" ]];then cmd=1 ; else cmd=0 ; fi ; fi
    if [[ "$package" == "slowdns" ]];then if process_is_running "slowdns";then cmd=0 ; else cmd=1 ; fi ; fi
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
    [[ $columns -le 78 ]] && line_separator 72 || line_separator 70
    printf "${WHITE}〢[ %-2s] ǂ %-12s ǂ %-31s ǂ %-15s〢\n" "#" "Servicio" "Puerto" "Estado"
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
            printf "〢${green}[ %-2s]${WHITE} ǂ ${green}%-12s${WHITE} ǂ ${green}%-31s${WHITE} ǂ ${green}%-15s${WHITE}〢\n" "$count" "$service" "$ports_used_by_service" "ACTIVO"
            array_service+=("$count:$ports_used_by_service")

        else
            (( count-- ))
            printf "〢${red}[ %-2s]${WHITE} ǂ ${red}%-12s${WHITE} ǂ ${red}%-31s${WHITE} ǂ ${red}%-15s${WHITE}〢\n" "-" "$service" "-" "INACTIVO"
        fi
    done
    [[ $columns -le 78 ]] && line_separator 72 || line_separator 70
    printf "${WHITE}〢${YELLOW}[ %-2s ]${WHITE} %-32s %35s\n" "10" "UTILIZAR UN PUERTO PERSONALIZADO" "〢"
    [[ $columns -le 78 ]] && line_separator 72 || line_separator 70
    while true;do
        read  -r -p "$(echo -e "${WHITE}[*] Ingrese el numero del servicio al que desea redireccionar: ")" service_number
        if [[ -z "$service_number" ]]; then continue ; fi
        if grep -E "[a-z]|[A-Z]" <<< "$service_number" &>/dev/null;then continue ; fi
        if [[ $service_number -lt 1 ]] || [[ $service_number -gt 10 ]]; then continue ; fi
        local port_number
        local port_list=(${array_service[$service_number-1]})
        local port_random=${port_list[0]}
        port_number=$(echo "${port_random}" | awk -F ":" '{print $2}')
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
    info "Listando certificados SSL en el directorio ${GREEN}$cert_dir${WHITE}"
    certs=$(ls ${user_folder}/FenixManager/cert-ssl/)
    
    if [[ -z "$certs" ]] ;then error "No hay certificados." ; return 1 ;fi
    line_separator 55
    printf "〢 ${blue}%-2s ${green}%-25s ${yellow}%-25s\n" '#' 'Nombre' 'Fecha de creacion' 
    line_separator 55

    for i in $certs;do
        (( count_ ++ ))
        certs_array+=("$i")
        date_=$(date -r "$cert_dir$i" +"%d/%m/%Y")
        local length_=$(echo 54 - ${#count_} - ${#i} - ${#date_} | bc)
        printf "${WHITE}〢${blue}[%-${#count_}s] ${green}%-${#i}s ${yellow}%-${#date_}s ${WHITE} %${length_}s\n" "$count_" "$i" "$date_" "〢"
    done
    line_separator 55
    
    while true;do
        read -r -p "$(echo -e "${green}[*] Selecciona un certificado (*.cert,*.pem,*.crt): ")" cert_opt
        if [[ -z "$cert_opt" ]] || [[ $cert_opt -gt $count_ ]];then
            continue
        else
            CERT_FILE=$cert_dir${certs_array[$cert_opt-1]}
            break
        fi
    done
    if [[ $CERT_FILE =~ "pem" ]];then return 0 ; fi
    while true;do
        read -r -p "$(echo -e" ${yellow}'[*] Selecciona una llave privada (*.key): '")" key_file
        if [[ -z "$key_file" ]] || [[ $key_file -gt $count_ ]];then continue ; fi
        export KEY_FILE="${cert_dir}${certs[$key_file]}"
        break
    done

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
                continue
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
    info "Listando banners en el directorio ${GREEN}${banners_dir}${WHITE}"
    local banners_array=($(ls "${banners_dir}/"))
    [[ $columns -le 78 ]] && {
            line_separator 72
            printf "${WHITE}〢 %-4s %-25s %-22s %-10s %-10s\r" "ID" "Nombre" "Tamaño" "Fecha de creacion" "〢"
        } || {
            line_separator 79
            printf "${WHITE}〢 %-4s %-22s %-22s %-30s〢\n" "ID" "Nombre" "Tamaño" "Fecha de creacion"
        }
    for (( i=0; i<(${#banners_array[*]}); i++ ));do
        local file="${banners_array[$i]}"
        local fullpath_file="${banners_dir}${file}"
        local file_size="$(du -sh ${fullpath_file} | cut -f1)"
        local file_date=$(stat -c %y "${fullpath_file}" | cut -d " " -f 1)
        local lenght_date=${#file_date}
        [[ $columns -le 78 ]] && {
            printf "${WHITE}〢 %-4s %-25s %-22s %-10s %9s\n" "$i" "$file" "$file_size" "$file_date" "〢"
        } || {
            printf "${WHITE}〢 %-4s %-30s %-21s %-21s %2s\n" "$i" "$file" "$file_size" "$file_date"  "〢"
        }
    done 
    [[ $columns -le 78 ]] && line_separator 72 || line_separator 79
    while true;do
        read -r -p "$(echo -e "${YELLOW}[*] Ingrese el ID del banner que desea utilizar: ")" banner_id
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
    # * print_format :
    # *  0 | table = table mode
    # *  1 | simple = simple for used in templates user

    local print_format="${1}"
    [[ "${print_format}" == "table" ]] && {
        local list_services=(sshd dropbear stunnel4 squid shadowsocks-libev pysocks openvpn x-ui)
    } || {
        local list_services=(sshd dropbear stunnel4 squid pysocks)
    }
    for services_ in "${list_services[@]}";do
        if [[ "${services_}" == "pysocks" ]];then
            systemctl status "fenixmanager-pysocks" &>/dev/null
        else
            systemctl status "$services_" &>/dev/null
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
                local port_listen=$(service dropbear status 2>/dev/null | grep -Eo " -p [0-9]{0,9}" |  sed "s/-p/ /g" | xargs)
                ;;
            "stunnel4")
                local port_listen=$(service stunnel4 status 2>/dev/null | grep -Eo ":::[0-9]{0,9}" | tr ":::" " " | xargs )
                ;;
            "squid")
                local port_listen=$(service squid status  2>/dev/null | grep -Eo "local=.*" | grep -Eo ":[0-9]{0,9}" | sed "s/:/ /g" | xargs)
                ;;
            "pysocks")
                local port_listen=$(systemctl status fenixmanager-pysocks 2>/dev/null | grep -Eo "\[#[0-9]\].*" | cut -d: -f3 | awk '{split($0,a," "); print a[1]}' | xargs)
                ;;
            "shadowsocks-libev")
                local port_listen=$(service shadowsocks-libev status 2>/dev/null | grep -Eo "tcp server .*" | awk '{split($0,a,":"); print a[2]}' | xargs )
                ;;
            "openvpn")
                local is_running=$(service openvpn@server status &>/dev/null;echo $?)
                [[ "${is_running}" == 0 ]] && local port_listen=$(cat /etc/openvpn/server.conf | grep -E 'port [0-9]{0,}' | grep -Eo '[0-9]{4,5}' | xargs )  || local port_listen="" 
                ;;
            "v2ray")
                local is_running=$(service v2ray status &>/dev/null;echo $?)
                [[ "${is_running}" == 0 ]] && local port_listen="configurar puertos desde x-ui"  || local port_listen="" 
                ;;
            "x-ui")
                local port_listen=$(service x-ui status 2>/dev/null | grep -Eo "\[\::\]:.*" | awk '{split($0,a,":"); print a[4]}' | xargs 2>/dev/null)
                ;;
        esac
        [[ "${print_format}" == "table" ]] && {
            [[ $columns -le 78 ]] && {
                printf "${WHITE}〢 ${color_}%-20s ${WHITE}|  ${YELLOW}%-30s ${WHITE}| ${color_}%-12s ${WHITE}%$(echo 66 - 20 - 30 - 12  | bc )s \n" "${services_^^}" "${port_listen}" "${status_^^}" "〢"   
            } || {
                printf "${WHITE}〢 ${color_}%-20s ${WHITE}|  ${YELLOW}%-30s ${WHITE}| ${color_}%-12s ${WHITE}%$(echo 81 - 20 - 30 - 12  | bc )s\n" "${services_^^}" "${port_listen}" "${status_^^}" "〢"   
            }
        } || {
            # ! 76
            [[ -z "${port_listen}" ]] && continue || {
            printf "${WHITE} ${color_} %-20s %20s ${WHITE} %$(echo 72 - 40  | bc)s\n" "${services_^^}" "${port_listen}"
            }
        }
    done
}

add_cron_job_for_hitman(){
    local fenixmanager_crontab="/etc/cron.d/fenixmanager"
    info "Agregando tarea crontab para hitman."
    info "Se crea el archivo ${GREEN}${fenixmanager_crontab}."
    echo "#!/bin/bash" > "${fenixmanager_crontab}"
    info "Se agrega la tarea crontab para hitman."
    local str_cront="@daily root $script_dir/funciones/hitman.bash 1"
    local str_cront+="\n*/15 * * * * root $script_dir/funciones/hitman.bash 2 "
    echo -e "$str_cront" >> "${fenixmanager_crontab}"
    info "Los usuarios vencidos se eliminan a las 00:00 ( Hora local )."
    info "Cada 15 minutos, hitman comprobara si los usuarios superaron el maximo de conexiones permitidas, si es asi, se eliminaran."
}

add_cron_job_for_udpgw(){
    local badvpn_udpgw="/etc/FenixManager/bin/badvpn-udpgw"
    local fenixmanager_crontab="/etc/cron.d/fenixmanager"
    info "Se agrega la tarea crontab para badvpn-udpgw."
    info "Por defecto,updgw escuchara en la direccion 127.0.0.1:7300 ."
    echo -e "\n@reboot root ${badvpn_udpgw} --listen-addr 127.0.0.0.1:7300" >> "${fenixmanager_crontab}"

}

show_users_and_port_template(){
    local user_data usuario passwd exp_date max_conn
    local head_banner="╔══════════════════║${RED}FENIX-MANAGER-V1.0${WHITE}║══════║${RED}@M1001-BYTE${WHITE}║════════════════╗"
    
    user_data=("${@}")
    usuario="${user_data[0]}"
    passwd="${user_data[1]}"
    exp_date="${user_data[2]}"
    max_conn="${user_data[3]}"
    
    echo -e "${head_banner}"
    #printf "║%76s\n" "║"
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

