#!/bin/bash
clear

user=$(logname)

script_name=`basename "$0"`
script_folder='/etc/FenixManager'
[[ "${user}" == "root" ]] && userfolder="/root" || userfolder="/home/${user}"

packets_to_install=(apt-transport-https python3 python3-pip neovim htop fail2ban sqlite3 debsums zip unzip mlocate ufw net-tools jq git make cmake htmlmin at)
updates_command=(update full-upgrade autoremove)
pip_packages=(colorama argparse requests)

if [ $(id -u) -ne 0 ]; then
    error "Este escrip debe ser ejecutado como root: sudo ./$script_name"
    exit 1
fi

mkdir /var/log/FenixManager/ &>/dev/null

clone_fenix(){
    trap "exit 130" SIGINT SIGTERM
    echo -e "\\033[34m〢────────────────〢 \\033[1;37mCLONANDO FENIXMANAGER \\033[34m〢─────────────────〢"
    local branch="master"
    local gitlog=$(mktemp -t gitlog.XXXXXXXX)
    
    local url="https://github.com/M1001-byte/FenixManager"
    if [ -d /etc/FenixManager ];then
        info "${GREEN}/etc/FenixManager${WHITE} ya existe, se procede a eliminar."
        rm -rf /etc/FenixManager/ &>/dev/null
    fi
    git clone -b "master" $url /etc/FenixManager
    
    if [ $? -ne 0 ];then
        error 'Fallo al clonar el repositorio.'
        info "Archivo de log: $gitlog/"
        exit $?
    fi
    
    chmod -R 777 /etc/FenixManager
    
    [ -f "/etc/FenixManager/preferences.bash" ] && rm -rf "/etc/FenixManager/preferences.bash"

    echo -e 'alias fenix="sudo /etc/FenixManager/main.bash"' >> "${userfolder}/.bashrc"
    echo "#!/bin/bash" > "/etc/FenixManager/preferences.bash"
    echo "# No modificar " >> "/etc/FenixManager/preferences.bash"
    echo "user_folder='${userfolder}'" >> "/etc/FenixManager/preferences.bash"
    echo "script_dir='${script_folder}'" >> "/etc/FenixManager/preferences.bash"
    echo "branch_clone='${branch}'" >> "/etc/FenixManager/preferences.bash"
    local version_for_branch=$(curl -s "https://raw.githubusercontent.com/M1001-byte/FenixManager/${branch}/version")
    echo "version='${version_for_branch}'" >> "/etc/FenixManager/preferences.bash"


}

change_dns(){
    chattr -i /etc/resolv.conf &>/dev/null
    mv /etc/resolv.conf /etc/resolv.conf.bak
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 1.0.0.1" > /etc/resolv.conf
    chattr +i /etc/resolv.conf
}

clone_fenix(){
    trap "exit 130" SIGINT SIGTERM
    echo -e "\\033[34m〢────────────────〢 \\033[1;37mCLONANDO FENIXMANAGER \\033[34m〢─────────────────〢"
    local branch="master"
    local gitlog=$(mktemp -t gitlog.XXXXXXXX)
    
    local url="https://github.com/M1001-byte/FenixManager"
    if [ -d /etc/FenixManager ];then
        info "${GREEN}/etc/FenixManager${WHITE} ya existe, se procede a eliminar."
        rm -rf /etc/FenixManager/ &>/dev/null
    fi
    git clone -b "master" $url /etc/FenixManager
    
    if [ $? -ne 0 ];then
        error 'Fallo al clonar el repositorio.'
        info "Archivo de log: $gitlog/"
        exit $?
    fi
    
    chmod -R 777 /etc/FenixManager
    
    [ -f "/etc/FenixManager/preferences.bash" ] && rm -rf "/etc/FenixManager/preferences.bash"

    echo -e 'alias fenix="sudo /etc/FenixManager/main.bash"' >> "${userfolder}/.bashrc"
    echo "#!/bin/bash" > "/etc/FenixManager/preferences.bash"
    echo "# No modificar " >> "/etc/FenixManager/preferences.bash"
    echo "user_folder='${userfolder}'" >> "/etc/FenixManager/preferences.bash"
    echo "script_dir='${script_folder}'" >> "/etc/FenixManager/preferences.bash"
    echo "branch_clone='${branch}'" >> "/etc/FenixManager/preferences.bash"
    local version_for_branch=$(curl -s "https://raw.githubusercontent.com/M1001-byte/FenixManager/${branch}/version")
    echo "version='${version_for_branch}'" >> "/etc/FenixManager/preferences.bash"
    return 0
}

update_system(){
    echo -e "${BLUE}〢───────────────〢 ${WHITE}ACTUALIZANDO EL SISTEMA ${BLUE}〢────────────────〢${WHITE}"
    for i in "${updates_command[@]}" ; do
        bar "apt-get $i -y" || {
           if [ $? -eq 130 ];then
               error 'Accion cancelada.'
                exit 130
           else
               error "Fallo al instalar $packets."
               info 'Pruebe ejecutando manualmente: sudo dpkg --configure -a '
                exit $?
            fi
        }
    done
}

install_packets(){
    echo -e "${BLUE}〢────────────〢 ${WHITE}INSTALANDO PAQUETES NECESARIOS ${BLUE}〢────────────〢${WHITE}"
    for packets in "${packets_to_install[@]}" ; do
        bar "$packets" "apt-get install $packets -y"  || {
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
    echo -e "${BLUE}〢───────────〢 ${WHITE}INSTALANDO PAQUETES DE PYTHON3 ${BLUE}〢─────────────〢${WHITE}"
    for i in "${pip_packages[@]}" ; do
        bar "$i" "pip3 install $i" || {
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
    # disabled ipv6
    sed -i "s/IPV6=yes/IPV6=no/" "${ufw_file}" &>/dev/null
}

initial(){
    change_dns
    clone_fenix && {
        source "/etc/FenixManager/funciones.bash"
        source "/etc/FenixManager/color.bash"
    }
    update_system
    install_packets
    install_python3_package
    add_basic_ufw_rules
    config_bashrc
    chmod -x /etc/update-motd.d/* & > /dev/null # remove all motd message
    info 'Su VPS se reiniciara.'
    read -p 'Presione [Enter] para reiniciar.'
    reboot

}

initial
