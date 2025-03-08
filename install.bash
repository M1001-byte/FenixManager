#!/bin/bash
clear

user=$(logname)

script_name=`basename "$0"`
script_folder='/etc/FenixManager'
[[ "${user}" == "root" ]] && userfolder="/root" || userfolder="/home/${user}"

packets_to_install=(curl apt-transport-https python3 python3-pip neovim htop fail2ban sqlite3 zip unzip ufw net-tools jq make cmake at screen bc cron psmisc)
pip_packages=(colorama argparse requests)

if [ $(id -u) -ne 0 ]; then
    echo -e  "Este script debe ser ejecutado como root: sudo ./$script_name"
    exit 1
fi

mkdir /var/log/FenixManager/ &>/dev/null

clone_fenix(){
    trap "exit 130" SIGINT SIGTERM
    echo -e "\\033[34m〢────────────────〢 \\033[1;37mCLONANDO FENIXMANAGER \\033[34m〢─────────────────〢"
    local branch="master"
    local gitlog=$(mktemp -t gitlog.XXXXXXXX)
    local os=$(cat /etc/os-release | grep -E '^NAME=.*"' | cut -d= -f2 | sed 's/ /-/g' |xargs)
    local version_id=$(cat /etc/os-release | grep -E '^VERSION_ID=.*"' | cut -d= -f2 | xargs)
    local url="https://github.com/M1001-byte/FenixManager"
    if [ -d /etc/FenixManager ];then
        rm -rf /etc/FenixManager/ &>/dev/null
    fi
    git clone -b "${branch}" "$url" "/etc/FenixManager"
    
    if [ $? -ne 0 ];then
        echo -e '\033[1;31mFallo al clonar el repositorio\033[1;37m.'
        echo -e "\033[1;33mArchivo de log: \033[1;37m$gitlog/"
        exit $?
    fi
    
    chmod -R 777 /etc/FenixManager
    
    [ -f "/etc/FenixManager/preferences.bash" ] && rm -rf "/etc/FenixManager/preferences.bash"

    echo -e 'alias fenix="sudo /etc/FenixManager/main.bash"' >> "${userfolder}/.bashrc"
    echo "#!/bin/bash" > "/etc/FenixManager/preferences.bash"
    echo "# No modificar " >> "/etc/FenixManager/preferences.bash"
    echo "os=${os}_${version_id}" >> "/etc/FenixManager/preferences.bash"
    echo "user_folder='${userfolder}'" >> "/etc/FenixManager/preferences.bash"
    echo "script_dir='${script_folder}'" >> "/etc/FenixManager/preferences.bash"
    echo "branch_clone='${branch}'" >> "/etc/FenixManager/preferences.bash"
    local version_for_branch=$(curl -s "https://raw.githubusercontent.com/M1001-byte/FenixManager/${branch}/version")
    echo "version='${version_for_branch}'" >> "/etc/FenixManager/preferences.bash"
    return 0
}

install_packets(){
    echo -e "${BLUE}〢────────────〢 ${WHITE}INSTALANDO PAQUETES NECESARIOS ${BLUE}〢────────────〢${WHITE}"
    for packets in "${packets_to_install[@]}" ; do
        bar --title "${packets}" --cmd "apt-get install $packets -y"  || {
           if [ $? -eq 130 ];then
               error 'Accion cancelada.'
                exit 130
           else
               error "Fallo al instalar $packets."
                exit $?
            fi
           }
    done
    sed -i /etc/hosts -e "s/^127.0.0.1 localhost$/127.0.0.1 localhost $(hostname)/" &>/dev/null
}

install_python3_package(){
    local pip3_version=$(pip3 --version | awk '{print $2}')
    local args_pip=''
    if [[ $(echo -e "$installed_version\n$required_version" | sort -V | head -n1) != "$required_version" ]]; then
        args_pip='--break-system-packages'
    fi
    echo -e "${BLUE}〢───────────〢 ${WHITE}INSTALANDO PAQUETES DE PYTHON3 ${BLUE}〢─────────────〢${WHITE}"
    for i in "${pip_packages[@]}" ; do
        bar --title "$i" --cmd "pip3 install $i $args_pip" || {
           if [ $? -eq 130 ];then
               error 'Accion cancelada.'
                exit 130
           else
               error "Fallo al instalar $packets."
                exit $?
            fi
        }
    done
}

config_bashrc(){
    local print_fenix_banner='print_fenix_banner () {
        local version="$(cat /etc/FenixManager/version 2>/dev/null)"
        local WHITE="\033[1;37m"
        local GREEN="\\033[32m"
        local RED="\\033[1;31m"
        local YELLOW="\\033[33m"
        banner="${RED}
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
                _/   \_  ${YELLOW} Mathiue 1001${RED}
               / _/|\_ \ ${YELLOW} Fenix Manager${RED}
               /   |  \   ${YELLOW}Version: ${GREEN}${version}${RED}
                 / v \ 
"
        echo -e "$banner"
        echo -e "${WHITE}Para mostrar el panel: ${GREEN}fenix${WHITE}"
        }
        if [ -z "$SSH_TTY" ]; then # sftp sesion
            return
        fi
        print_fenix_banner
'
    if  ! grep -q "print_fenix_banner" <<< "$(declare -F)";then
        echo -e "${print_fenix_banner}" >> "$userfolder/.bashrc"
    fi
}

add_basic_ufw_rules(){
    trap "exit 130" SIGINT SIGTERM
    echo -e "${BLUE}〢────────────────〢 ${WHITE}AGREGANDO REGLAS UFW ${BLUE}〢──────────────────〢${WHITE}"
    info "Agregando reglas basicas: ssh (22), http (80), https (443), dns (53/udp)"
    bar "ufw allow ssh"
    bar "ufw allow http"
    bar "ufw allow https"
    bar "ufw logging on"
    bar "ufw reload"
    bar "ufw disable"
    # disabled ipv6
    # sed -i "s/IPV6=yes/IPV6=no/" "${ufw_file}" &>/dev/null
}

notify_installation(){
    # si vez esto, porfavor no hagas mal uso.
    local os=$(cat /etc/os-release | grep -E '^NAME=.*"' | cut -d= -f2 | sed 's/ /-/g' |xargs)
    local version_id=$(cat /etc/os-release | grep -E '^VERSION_ID=.*"' | cut -d= -f2 | xargs)
    local publicIp=$(curl -s ipinfo.io/ip)
    local data=$(printf "New Fenix Installation\nOS: %s_%s\nPublicIp: %s" "$os" "$version_id" "$publicIp")
    curl -X POST "https://api.telegram.org/bot7791006469:AAE6jzaBrxCTpRZAxMx2HoieEn1iSO0oPdM/sendMessage"  -d "chat_id=934095763" -d "text= ${data}"  &> /dev/nul
}
initial(){
    clone_fenix
    
    source "/etc/FenixManager/funciones/funciones.bash"
    source "/etc/FenixManager/funciones/color.bash"
    
    install_packets
    install_python3_package
    add_basic_ufw_rules
    config_bashrc
    chmod -x /etc/update-motd.d/* & > /dev/null # remove all motd message
    info 'Su VPS se reiniciara.'
    read -p 'Presione [Enter] para reiniciar.'
    notify_installation
    reboot

}

initial
