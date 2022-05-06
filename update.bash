#!/bin/bash
source "/etc/FenixManager/funciones/funciones.bash"

check_update(){
    local remote_version=$(curl -s https://raw.githubusercontent.com/M1001-byte/FenixManager/master/version)
    local current_version=$(cat /etc/FenixManager/version)
    [[ -z "${current_version}" ]] && error "Fallo al obtener la version local."
    [[ -z "${remote_version}" ]] && error "Fallo al obtener la version remota. Comprueba tu conexion a internet."
    
    if [[ "${remote_version}" == "${current_version}" ]];then
        info "Tu version de Fenix Manager es la mas reciente"
    else
        info "Hay una ${GREEN}nueva version${WHITE} de Fenix Manager disponible"
        info "Tu version: ${current_version}"
        info "Nueva version: ${version}"
        read -p "[*] Deseas actualizar? [Y/n] " opt
        case $opt in
            y|Y|S|s)
                    info "Actualizando..."
                    sleep 1
                    rm -rf /tmp/FenixManager-old
                    mkdir /tmp/FenixManager-old 2>/dev/null
                    mv -t /tmp/FenixManager-old "${script_dir}/database/" "${script_dir}/ip" "${script_dir}/preferences.bash" || {
                        error "Ocurrio un error. La actualizacion no pudo ser completada."
                        exit $?
                    }
                    rm -rf "/etc/FenixManager/*"
                    git clone "https://github.com/M1001-byte/FenixManager.git" /etc/FenixManager || {
                        error "Ocurrio un error. La actualizacion no pudo ser completada."
                        exit $?
                    }
                    # /tmp/FenixManager-bak
                    mv -t /etc/FenixManager/ /tmp/FenixManager-old/* 

                    local fenix_bash_files=$(find /etc/FenixManager/ -name "*.bash")
                    for file in $fenix_bash_files; do chmod 777 $file &>/dev/null ; done
                    info "Fenix Manager se actualizo correctamente"
                ;;
            *)
                info "Fenix Manager no se actualizo"
                ;;
        esac
    fi
}

check_update