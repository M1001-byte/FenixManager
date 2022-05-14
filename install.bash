#!/bin/bash
clear
ctrl_c() {
        kill -9 $!
        exit 130
}

info(){ echo -e "\\033[1;33m[INFO]\\033[m \\033[1;37m$*\\033[m";}
error() { echo -e "\\033[1;31m[ERROR]\\033[m \\033[1;37m$*\\033[m";}

bar() {
    local str="###############"
    local s=0.25
    if [ -z "$2" ]; then
        local bg_process="$1"
        local textshow="$1"
    else
        local textshow="$1"
        local bg_process="$2"
    fi
    local tmpfile=$(mktemp -t progress.XXXXXXXX)
    echo $text
    
    # colors var
    local green='\033[32m'
    local red='\033[31m'
    local yellow='\033[33m'
    local end='\033[0m'
    
 
    while true;do 
        for i in {1..14}; do
            sleep 0.25
            s=$(echo ${s} + 0.25| bc)
            printf "\33[2K\r[ $yellow%s$end ] $green[%-16s $end%s" "$textshow" "${str:0:$i}]" " ET: ${s}s"  | tee $tmpfile # save time 
            done
        done  & local while_pid=$!

    trap "kill -9 $while_pid" SIGINT SIGTERM 
    
    ${bg_process} &> /dev/null || STAT=$? && true
    trap "kill -9  $!" SIGINT SIGTERM SIGKILL
    kill $! &> /dev/null
    local endtime=$(cat $tmpfile | awk '{split($0,a,"ET:");print a[2] }')
    
    #Si el proceso termino en menos de 1 segundo
    if [[ -z "${endtime}" ]]; then
        local endtime="0.00s"
    fi
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

    printf "\33[2K\r[ $yellow%s$end ] $result_color[%-15s]$end [$result_color%s$end] %s \n" "$textshow" "${str}" "${result}" " ET: ${endtime}"
    rm -f ${tmpfile}
    return $STAT

}

user=$(logname)

script_name=`basename "$0"`
script_folder='/etc/FenixManager'
[[ "${user}" == "root" ]] && userfolder="/root" || userfolder="/home/${user}"

packets_to_install=(apt-transport-https python3 python3-pip neovim htop fail2ban sqlite3 debsums zip unzip mlocate ufw net-tools jq)
updates_command=(update full-upgrade autoremove)
pip_packages=(colorama argparse requests)

if [ $(id -u) -ne 0 ]; then
    error "Este escrip debe ser ejecutado como root: sudo ./$script_name"
    exit 1
fi

mkdir /var/log/FenixManager/ &>/dev/null

change_dns(){
    chattr -i /etc/resolv.conf &>/dev/null
    mv /etc/resolv.conf /etc/resolv.conf.bak
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 1.0.0.1" > /etc/resolv.conf
    chattr +i /etc/resolv.conf
}

update_system(){
    echo -e "\\033[34m〢───────────────〢 \\033[1;37mACTUALIZANDO EL SISTEMA \\033[34m〢────────────────〢"
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
    echo -e "\\033[34m〢────────────〢 \\033[1;37mINSTALANDO PAQUETES NECESARIOS \\033[34m〢────────────〢"
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
    echo -e "\\033[34m〢───────────〢 \\033[1;37mINSTALANDO PAQUETES DE PYTHON3 \\033[34m〢─────────────〢"
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
    local bashrc_banner='YmFubmVyPSdHMXN4T3pNeGJRb2dJQ0FnSUNBZ0lDQWdJQ0FnWHk5OElDQWdJQ0FnSUh4Y1h3b2dJQ0FnSUNBZ0lDQWdJQ0F2SUNCOElDQWdJQ0FnSUh3Z0lGd2dDaUFnSUNBZ0lDQWdJQ0FnZkNBZ0lDQmNJQ0FnSUNBdklDQWdJSHdLSUNBZ0lDQWdJQ0FnSUNCOElDQmNJQzhnSUNBZ0lGd2dMeUFnZkFvZ0lDQWdJQ0FnSUNBZ0lId2dYQ0FnZkNBZ0lDQWdmQ0FnTHlCOENpQWdJQ0FnSUNBZ0lDQWdmQ0JjSUY5Y1h5OWVYRjh2WHlBdklId0tJQ0FnSUNBZ0lDQWdJQ0I4SUNBZ0lDMHRYQzh2TFMwZ0lDQWdmQW9nSUNBZ0lDQWdJQ0FnSUNCY1h5QWdYQ0FnSUNBZ0x5QWdYeThLSUNBZ0lDQWdJQ0FnSUNBZ0lDQmNYMThnSUh3Z0lGOWZMd29nSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJRndnWHlBdkNpQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNCZkx5QWdJRnhmRzF0dElCdGJNek50SUNBZ0lFMWhkR2hwZFdVZ01UQXdNUnRiYlFvZ0lDQWdJQ0FnSUNBZ0lDQWdJQnRiTVRzek1XMGdMeUJmTDN4Y1h5QmNJQnRiYlNBYld6TXpiU0FnUm1WdWFYZ2dUV0Z1WVdkbGNodGJiUW9nSUNBZ0lDQWdJQ0FnSUNBZ0lDQWJXekU3TXpGdElDOGdJSHdnSUZ3Z0lDQWJXek16YlNBZ1ZtVnljMmx2YmpvZ01TNHdMakFiVzIwS0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUJ0Yk1Uc3pNVzBnTHlCMklGd2dDZz09JwplY2hvIC1lICRiYW5uZXIgfCBiYXNlNjQgLS1kZWNvZGUKZWNobyAtZSAiIFxcMDMzWzE7MzdtQmllbnZlbmlkbyBhIFxcMDMzWzE7MzNtRmVuaXggTWFuYWdlclxcMDMzW20iCmVjaG8gLWUgIlxcMDMzWzE7MzdtIFBhcmEgdGVybWluYXIgZWwgcHJvY2VzbyBkZSBpbnN0YWxhY2lvbixlamVjdXRhciBlbCBzaWd1aWVudGUgY29tYW5kbzpcXDAzM1ttIFxcMDMzWzE7MzJtZmVuaXhcXDAzM1ttICIK'
    
    [[ "${user}" != "root" ]] && {
        echo -e $bashrc_banner | base64 -d >> "/home/${user}/.bashrc"
        echo "alias fenix='sudo $script_folder/main.bash'" >> "/home/${user}/.bashrc"
    } || {
        echo -e $bashrc_banner | base64 -d >> "$userfolder/.bashrc"
        echo "alias fenix='sudo $script_folder/main.bash'" >> "$userfolder/.bashrc"
    
    }
}

add_basic_ufw_rules(){
    trap "exit 130" SIGINT SIGTERM
    echo -e "\\033[34m〢────────────────〢 \\033[1;37mAGREGANDO REGLAS UFW \\033[34m〢──────────────────〢"
    info "Agregando reglas basicas: ssh (22), http (80), https (443), dns (53/udp)"
    bar "ufw allow ssh"
    bar "ufw allow http"
    bar "ufw allow https"
    # disabled ipv6
    bar "ufw logging on"
    bar "ufw reload"
    sed -i "s/IPV6=yes/IPV6=no/" "${ufw_file}" &>/dev/null
}



clone_fenix(){
    trap "exit 130" SIGINT SIGTERM
    echo -e "\\033[34m〢────────────────〢 \\033[1;37mCLONANDO FENIXMANAGER \\033[34m〢─────────────────〢"
    
    local gitlog=$(mktemp -t gitlog.XXXXXXXX)
    echo -e "Ingrese la rama a usar:\n1) \\033[32mmaster\\033[m\n2) \\033[33mdev\\033[m\n3) \\033[32msimple ui\\033[mLa opcion por defecto es \\033[32mmaster\\033[m.La rama \\033[33mdev\\033[m es una rama de desarrollo."
    read -p "[*] Desde que rama deseas clonar el repositorio: " branch
    if [ -z "${branch}" ]; then
        local branch='master'
    elif [ "${branch}" == "1" ]; then
        local branch='master'
    elif [ "${branch}" == "2" ]; then
        local branch='dev'
    elif [ "${branch}" == "3" ]; then
        local branch='simple-ui'
    else
        local branch='master'
    fi

    local url="https://github.com/M1001-byte/FenixManager"
    bar "git clone -b $branch $url" "git clone -b $branch $url /tmp/FenixManager "
    if [ $? -ne 0 ];then
        error 'Fallo al clonar el repositorio.'
        info "Archivo de log: $gitlog/"
        exit $?
    fi
    if [ -d /etc/FenixManager ];then
        rm -rf /etc/FenixManager/* -rf
    else
        mkdir /etc/FenixManager/ &>/dev/null
    fi
    
    mv /tmp/FenixManager/* /etc/FenixManager/
    local fenix_bash_files=$(find /etc/FenixManager/ -name "*.bash")
    for file in $fenix_bash_files; do
        chmod 777 $file &>/dev/null
    done
    sudo rm -rf /tmp/FenixManager/
    echo "#!/bin/bash" > "/etc/FenixManager/fenixmanager.bash"
    echo "# No modificar " >> "/etc/FenixManager/fenixmanager.bash"
    echo "user_folder='${userfolder}'" > "/etc/FenixManager/preferences.bash"
    echo "script_dir='${script_folder}'" >> "/etc/FenixManager/preferences.bash"
    echo "branch_clone='${branch}'" >> "/etc/FenixManager/preferences.bash"
    local version_for_branch=$(curl -s "https://raw.githubusercontent.com/M1001-byte/FenixManager/${branch}/version")
    echo "version='${version_for_branch}'" >> "/etc/FenixManager/preferences.bash"
    echo "simple_ui='true'" >> "/etc/FenixManager/preferences.bash"


}

initial(){
    change_dns
    #update_system
    install_packets
    install_python3_package
    clone_fenix
    add_basic_ufw_rules
    config_bashrc
    chmod -x /etc/update-motd.d/* & > /dev/null # remove all motd message
    info 'Su VPS se reiniciara.'
    read -p 'Presione [Enter] para reiniciar.'
    reboot

}

initial
