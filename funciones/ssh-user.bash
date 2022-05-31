#!/bin/bash

current_dir=$(pwd)
userdb='/etc/FenixManager/database/usuarios.db'

source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/color.bash" 2>/dev/null

script_executed_with_root_privileges

create_temp_user(){
    info "Creando un usuario temporal"
    while true;do
        read -p "$(echo -e ${WHITE}'[*] Ingrese el valor en este formato ( 00H:00M ) : ' )" date_exp
        
        local date_exp=$(sed -e 's/[mM:]/ /g' <<< "${date_exp}" | sed -e 's/[hH]/ /g')
        IFS=' ' read -r -a tmp_time <<< "$date_exp"
        if [[ ${#tmp_time[@]} -eq 0 ]];then
            error "Valor incorrecto, se asignara una fecha de expiracion de 1 dia."
            date_exp=1
            break
        fi
        # check if hour is menor than 24
        if [[ ${tmp_time[0]} -gt 24 ]];then
            error "Valor incorrecto, al crear un usuario temporal, la hora no puede ser mayor a 24."
            continue
        fi
        # check if minute is menor than 60
        if [[ ${tmp_time[1]} -gt 60 ]];then
            error "Valor incorrecto, al crear un usuario temporal, los minutos no pueden ser mayores a 60."                
            continue
        elif [[ ${#tmp_time[1]} -eq 1 ]];then
            tmp_time[1]=0${tmp_time[1]}
        fi
        info "El usuario expira dentro de ${tmp_time[0]} hora/s y ${tmp_time[1]} minutos."
        [[ "${tmp_time[0]}" == 00 ]] && {
            at_time="now + ${tmp_time[1]} minutes"
            } || {
                at_time=$(date "+%H:%M" --date="+ ${tmp_time[0]} hour ${tmp_time[1]} minutes")
            }
        info "Los usuarios temporale no se guardan en la base de datos.Comprobar el registro de ${RED}HITMAN${WHITE} para ver cuado el usuario fue eliminado."
        break
        done
        
}

create_ssh_user_input() {
    local date_exp
    group_ssh='ssh_user'
    {   # check if group exist,and perl is installed
        if ! grep -q "^$group_ssh:" /etc/group; then groupadd $group_ssh ; fi
        if ! package_installed "perl"; then
            echo -e "${RED}Perl no está instalado en el sistema${WHITE}"
            bar "apt-get install perl -y"
            if [[ $? != 0 ]]; then
                echo -e "${RED}No se pudo instalar perl${WHITE}"
                exit 1
            fi
        fi
    }
    while true;do
        read -p "$(echo -e "$WHITE[*] Ingrese el nombre de usuario:${endcolor}") " user
    
        if [[ ${#user} -gt 32 ]];then
            error 'El nombre de usuario no puede tener mas de 32 caracteres.'
            continue
        fi
        if [[ -z $user ]];then
            error 'El nombre de usuario no puede estar vacio.'
            continue
        fi
        user=$(sed -e 's/ /_/g' <<< "${user}")
        check_user_exist "$user"
        if [ $? -eq 0 ];then
            while true;do
                read -p "$(echo -e $BLUE'[*] Alias (Opcional) : ' )" alias_
                if [[ ${#alias_} -gt 15  ]];then
                    error "El alias no puede tener mas de 15 caracteres."
                    continue
                fi
                if [[ -z $alias_ ]];then
                    alias_=''
                fi
                break
            done
            while true;do
                if [[ ! -z $alias_ ]];then
                    str="($alias_)"
                else
                    str=""
                fi
                # if lenght of user is greater than 18
                [[ ${#user} -gt 18 ]] && local user_tmp="${user:0:17}(~)" || local user_tmp="${user}"
                read -p "$(echo -e $YELLOW"[*] Contraseña para ${user_tmp} $str: " )" passwd
                if [[ ${#passwd} -gt 20 ]];then
                    error 'La contraseña no puede tener mas de 20 caracteres.'
                    continue
                fi
                if [[ -z "$passwd" ]];then
                    error 'La contraseña no puede estar vacia.'
                    continue
                else
                    break
                fi
            done
            
            

            until [[ "$date_exp" =~ ^[0-9]+$ ]];do
                read -p "$(echo -e $GREEN'[*] Cantidad de dias para expirar : ' )" date_exp
                if [[ "$date_exp" =~ ^-$ ]];then
                    create_temp_user
                elif [[ ! "${date_exp}" =~ ^[0-9]+$ ]];then
                    error "El valor ingresado no es valido."
                else
                    fecha_final=$(date -d "$date_exp days" +%Y-%m-%d 2>/dev/null)
                    fecha_final=($fecha_final + $(date +'%T'))
                    
                fi
            done
            
            until [[ "$max_connections" =~ ^[0-9]+$ ]];do
                read -p "$(echo -e $RED'[*] Cantidad maxima de conexiones : ' )" max_connections
                if [ -z "$max_connections" ];then
                    info 'El valor no es correcto.De forma predeterminada, se le asignara un maximo de una (1) conexion.'
                    max_connections=1
                    break
                fi
            done

            pass=$(perl -e 'print crypt($ARGV[0], "password")' $passwd)
            
            useradd -g "$group_ssh" --no-create-home --shell /bin/false --gid $group_ssh  -p "$pass" "$user"
	        if [[ $? -eq 0 ]];then
                [[ ! -z "${at_time}" ]] && {
                    local output=$(echo "/etc/FenixManager/funciones/hitman.bash 5 ${user} ${passwd}"| at "${at_time}" 2>&1)
                    local hours=$(echo "${output}" | awk 'NR==2{split($0,a," "); print a[7]}')
                    info "El usuario ${GREEN}$user${WHITE} se creo correctamente.Se eliminara a las ${GREEN}${hours}${WHITE} ( hora local )."
                    read -p "$(echo -e $GREEN'[*] Presione enter para continuar... ' )"
                } || {
                    if [[ -z $alias_ ]];then
                        cmd="insert into ssh (nombre,password,exp_date,max_conn) values ('$user','$passwd','$fecha_final','$max_connections')"
                    else
                        cmd="insert into ssh (nombre,alias,password,exp_date,max_conn) values ('$user','$alias_','$passwd','$fecha_final','$max_connections')"
                    fi

                    sqlite3 $userdb "$cmd"
                    if [[ ! $? -eq 0 ]];then
                        error 'No se pudo agregar el usuario a la base de datos'
                        userdel $user
                        
                    fi
                }
            else
                error 'Fallo la creacion del usuario.'
            fi
            break
            
        else
            continue
        fi
    done

}

list_user() {
    clear
    db="/etc/FenixManager/database/usuarios.db"
    # check if table exist
    {
        sqlite3 $db "SELECT name FROM sqlite_master WHERE type='table' AND name='ssh';" 2>&1 | grep 'ssh' &>/dev/null
        if [[ $? -eq 0 ]];then
            users_count=$(sqlite3 $db "select count(*) from ssh")
        else
            error 'LA TABLA SSH NO EXISTE EN LA BASE DE DATOS.'
            read -p "$(echo -e $WHITE'[*] Desea crearla (S)i (N)o : ' )" create_table
            if [[ "$create_table" == 's' ]] || [[ "$create_table" = 'S' ]];then
                sqlite3 $db  'CREATE TABLE ssh (nombre VARCHAR(20) NOT NULL, alias VARCHAR(10), password VARCHAR(15), exp_date DATETIME, max_conn INT NOT NULL );'
                info 'La tabla ssh fue creada con exito.'
                sleep 1
                clear
            else
                error 'La tabla ssh no existe en la base de datos'.
                error 'No se puede continuar con la ejecucion del script.'
                exit 1
            fi
        fi
    }

    local total_users=$(sqlite3 $db "select count(*) from ssh" &) 
    local users_connected=0

    lop=$(sqlite3 $db "select rowid, * from ssh")

    line_separator 64
    printf "${WHITE}〢${RED}%-32s${YELLOW}%-15s${BLUE}%12s${WHITE}%-6s〢\n" 'NOMBRE' 'CONTRASEÑA' 'EXPIRA'
    line_separator 64

    for i in $lop;do
        IFS='|' read -r -a var_val <<< "$i"
        
        id=${var_val[0]}
        user=${var_val[1]}
        number_session_openssh=$(ps auxwww | grep 'sshd:' | awk '{print $1 }' | grep -w -c "$user")
        process_is_running "dropbear" && {
            number_session_dropbear=$(ps auxwww | grep 'dropbear' | awk '{print $1 }' | grep -w -c "$user")
            number_session=$((number_session_openssh + number_session_dropbear))
        } || {
            number_session=$number_session_openssh
        }
        
        [[ ! "${number_session}" -eq 0 ]] && ((users_connected++))

        [[ -z ${var_val[2]} ]] && alias_='-' || alias_=${var_val[2]}

        [[ ${#user} -gt 25 ]] && user="${user:0:20}(~)" # ! (...)
        
        password=${var_val[3]}
        exp=${var_val[4]}
        conn="${number_session}/${var_val[5]}"
        printf "${WHITE}〢${RED}%-25s${WHITE}[${alias_}]${YELLOW} %-15s${BLUE} %10s${WHITE}\n" "${user}"  $password $exp
        
    done
    line_separator 64
    local users_disconnected=$(($total_users - $users_connected))
    local total_openssh_connections=$(ps auxwww | grep 'sshd:' | awk '{print $1 }' | wc -l)
    read -p "$(echo -e $GREEN'[*] Presione enter para continuar... ' )"


}

monitor_users(){
    local user_count=$(sqlite3 $userdb "select count(*) from ssh")
    local users_connected=0
    local users_disconnected=0
    clear
    line_separator 60
    
    printf "${WHITE}〢 ${RED}%-32s ${GREEN}%10s ${WHITE}/ ${YELLOW}%-10s${WHITE} %5s\n" "USUARIO" "CONEXIONES" "PERMITIDAS" "〢"
    line_separator 60
    for i in $(sqlite3 $userdb "select rowid, * from ssh");do
        IFS='|' read -r -a var_val <<< "$i"
        local max_conn=${var_val[5]}
        local user=${var_val[1]}
        number_session_openssh=$(ps auxwww | grep 'sshd:' | awk '{print $1 }' | grep -w -c "$user")
        process_is_running "dropbear" && {
            number_session_dropbear=$(ps auxwww | grep 'dropbear' | awk '{print $1 }' | grep -w -c "$user")
            number_session=$((number_session_openssh + number_session_dropbear))
        } || {
            number_session=$number_session_openssh
        }
        [[ ! "${number_session}" -eq 0 ]] && ((users_connected++))
        printf "${WHITE}〢 ${RED}%-32s ${GREEN}%10s ${WHITE}/ ${YELLOW}%-10s${WHITE} %5s${WHITE}\n" "${user}" "${number_session}" "${max_conn}" "〢"
    done
    line_separator 60
    read -p "$(echo -e $WHITE'[*] Presione ENTER para continuar...')"
    clear ; clo
}

list_id_user_simple(){
    local count_=0
    for i in $(sqlite3 $userdb "select rowid, * from ssh");do
        ((count_++))
        IFS='|' read -r -a var_val <<< "$i"
        local id=${var_val[0]}
        local username=${var_val[1]}
        local alias_=${var_val[2]}
        
        printf  "${WHITE}%-5s [ ${GREEN}${id}${WHITE} ] ${RED}${username} ${YELLOW}${alias_}${WHITE}\n"
    done
    [[ "${count_}" -eq 0 ]] && {
        error 'No hay usuarios registrados en la base de datos'.
        sleep 1.5
        fenix
    }
}

option_menu_ssh() {
    option_color '1' 'AGREGAR USUARIO'
    option_color '2' 'ELIMINAR USUARIO'
    option_color '3' 'EDITAR USURIO'      
    option_color "4" "LISTAR TODOS LOS USUARIOS"
    option_color "5" "MONITOR DE USUARIOS CONECTADOS"
    option_color '6' 'CREAR UN BACKUP DE LA BASE DE DATOS'
    option_color '7' 'RESTAURAR BACKUP DE LA BASE DE DATOS'
    option_color '8' "${RED}ELIMINAR TODOS LOS USUARIOS"

    option_color 'E' 'SALIR'
    option_color 'M' 'MENU PRINCIPAL'
    
    while true;do
        prompt=$(date "+%x %X")
        printf "\33[2K\r${WHITE}[$BBLUE${prompt}${WHITE}] : " 2>/dev/null && read   option
        case $option in
            1 ) create_ssh_user_input && clo ;;
            2 ) delete_user ;;
            3 ) edit_user ;;
            4 ) list_user ; clo ;;
            5 ) monitor_users ; clo ;;
            6 ) backup_user ;;
            7 ) restore_backup ;;
            8 ) delete_all_users_ssh ;;
            e | E | q | Q ) exit 0 ;;
            m | M ) fenix ;;
            "cls" | "Cls" | "CLS" ) clo ;;
            * ) tput cuu1 && tput el1 ;;
            esac
        done
}

delete_user () {
    list_id_user_simple 
    read -p "$(echo -e $WHITE'[*] Ingrese el id del usuario a eliminar : ' )" id_user
    local user_name=$(sqlite3 $userdb "select rowid,nombre from ssh where rowid = $id_user" 2>/dev/null| awk '{split($0,a,"|");print a[2]}')
    
    if [[ -z  "${user_name}" ]];then
        error "No existe un usuario con ese id. O no hay usuarios en la base de datos."
        return 1
    fi
    
    grep -q $user_name /etc/passwd
    if [[ $? != 0 ]];then
        error 'El usuario esta presente en la base de datos,pero no en el sistema.'
        sqlite3 $userdb "delete from ssh where nombre = '$user_name'"
        if [[ $? == 0 ]];then
            info 'Usuario eliminado de la base de datos'
        else
            error 'Fallo la eliminacion del usuario de la base de datos.'
        fi
    else
        pkill -u $user_name
        sqlite3 $userdb "delete from ssh where nombre = '$user_name'"
        userdel $user_name
        info  "El Usuario ${RED}${user_name}${WHITE} eliminado con exito."
    fi

    read -p "$(echo -e $WHITE'[*] Presione enter para continuar... ' )"
    clo
}

delete_all_users_ssh() {
    local return_clo="${1}"
    read -p "$(echo -e $RED'[*] Esta seguro de eliminar todos los usuarios (S)i (N)o : ' )" confirm
    case $confirm in
        S | s | y | y )
            info "Eliminando todos los usuarios."
            line_separator 51
            printf "${WHITE}〢 %-30s${YELLOW}%-20s${WHITE}〢\n" 'USUARIO' 'ESTADO'
            line_separator 51
            for user in $(sqlite3 $userdb "select nombre from ssh");do
                printf "${WHITE}〢 ${YELLOW}%-30s${WHITE}" "${user}"
                local user_del_sterr=$(userdel "${user}" 2>&1)
                [ -z "${user_del_sterr}" ] && {
                    printf "${GREEN}%-20s${WHITE}\n" '[ ELIMINADO ]'
                } || {
                    printf "${RED}%-20s${WHITE}\n" "[ $(grep -o "${user}.*" <<< "${user_add_stderr}" | cut -d "'" -f 2 | xargs) ]"
                }
            done
            sqlite3 $userdb "delete from ssh"
            [[ "${return_clo}" -eq 0 ]] && {
                read -p "$(echo -e $MAGENTA'[*] Presione enter para continuar.': )"
                clo
            } || {
                line_separator 51
                exit 0
            }
            ;;
        *)
            info "Operacion cancelada."
            read -p "$(echo -e $MAGENTA'[*] Presione enter para continuar.': )"
            clo
            ;;
    esac

}

edit_user () {
    all_ids=$(sqlite3 $userdb "select rowid,nombre from ssh" | awk '{split($0,a,"|");print a[1]}')
    list_id_user_simple
    read -p "$(echo -e $GREEN'[*] Ingrese el id del usuario a editar : ' )" id_user
    
    if [[ ! $all_ids =~ $id_user ]];then
        error 'El id ingresado no existe en la base de datos.'
        read -p "$(echo -e $MAGENTA'[*] Presione enter para continuar.': )"
        clo
    fi

    name=$(sqlite3 $userdb "select nombre from ssh where rowid = $id_user")
    info "Editando el usuario ${RED}$name${WHITE}.Presione enter si no deseas editar una opcion."

    while true;do
        read -p "$(echo -e $WHITE'[*] Ingrese el nuevo nombre del usuario : ' )" new_name
        if [[ ${#new_name} -gt 32 ]];then
            error 'El nombre de usuario no puede tener mas de 32 caracteres.'
            continue
        fi
        if [[ -z $new_name ]];then
            new_name=$name
            break
        else
            if ! check_user_exist $new_name;then
                continue
            fi
        fi
        break
    done
    default_password=$(sqlite3 $userdb "select password from ssh where rowid = $id_user")
    
    while true;do
        read -p "$(echo -e $MAGENTA'[*] Contraseña para '$new_name' : ')" password
        if [[ ${#password} -gt 20 ]];then
            error 'La contraseña no puede tener mas de 20 caracteres.'
            continue
        fi
        if [[ -z $password ]];then
             password=$default_password
             break
        fi
        break
    done
    
    exp_date_default=$(sqlite3 $userdb "select exp_date from ssh where rowid = $id_user")
    while true;do
        read -p "$(echo -e $RED'[*] Cantidad de dias a expirar : ' )" exp_date
    
        [[ -z $exp_date ]] && exp_date=$exp_date_default
        
        [[ $exp_date =~ ^[0-9]+$ ]] && exp_date=$(date -d "$exp_date days" +%Y-%m-%d 2>/dev/null) ; break
    done
    
    max_conn_default=$(sqlite3 $userdb "select max_conn from ssh where rowid = $id_user")
    while true;do
        read -p "$(echo -e $YELLOW'[*] Cantidad de conexiones permitidas : ' )" max_conn
    
        if [[ -z $max_conn ]];then
            max_conn=$max_conn_default
        fi
        [[ $max_conn =~ ^[0-9]+$ ]] &&  break
    done

    info "${RED}[!]${WHITE} = valor modificados. ${GREEN}[+]${WHITE} = valor por defecto"
    if [[ "$new_name" != "$name" ]];then
        printf "${RED}[!]${WHITE}Nombre de usuario : ${new_name}\n"
    else
        printf "${GREEN}[+]${WHITE}Nombre de usuario : $new_name\n"
    fi
    if [[ "$password" != "$default_password" ]];then
        printf "${RED}[!]${WHITE}Contraseña : ${password}\n"
    else
        printf "${GREEN}[+]${WHITE}Contraseña : ${password}\n"
    fi
    if [[ "$exp_date" != "$exp_date_default" ]];then
        printf "${RED}[!]${WHITE}Expiracion : ${exp_date}\n"
    else
        printf "${GREEN}[+]${WHITE}Expiracion :${exp_date}\n"
    fi
    if  [[ "$max_conn" != "$max_conn_default" ]];then
        printf "${RED}[!]${WHITE}Conexiones : ${max_conn}\n"
    else
        printf "${GREEN}[+]${WHITE}Conexiones : ${max_conn}\n"
    fi

    while true;do
        read -p "$(echo -e $GREEN'[*] Deseas salvar los cambios (S)i (N)o  (R)eeditar . : ' )" confirm
        case $confirm in
            s | S )
                sqlite3 $userdb "update ssh set nombre = '$new_name', password = '$password', exp_date = '$exp_date', max_conn = '$max_conn' where rowid = $id_user"
                pkill -9 -u $name &>/dev/null && userdel $name &>/dev/null
                local pass=$(perl -e 'print crypt($ARGV[0], "password")' $password)
                useradd -g "ssh_user" --no-create-home --shell /bin/false --gid "ssh_user"  -p "$pass" "$new_name"
                info "El usuaio $new_name ha sido editado con exito."
                read -p "$(echo -e $MAGENTA'[*] Presione enter para continuar.': )"
                clo
                ;;
            n | N )
                clo
                ;;
            r | R )
                edit_user
                ;;
            esac
    done
}

backup_user () {
    date_=$(date +%Y-%m-%d)
    local mk_file=$(mktemp)
    mkdir $user_folder/FenixManager/backup -p &> /dev/null
    database_file="$user_folder/FenixManager/backup/backup_usuarios_$date_.db"

    if [[ -e "$database_file" ]];then
        database_file="$user_folder/FenixManager/backup/backup_usuarios_$date_(1).db"
    fi

    database=$(sqlite3 $userdb ".dump" > $database_file)
    
    if [[ $status -eq 0 ]];then

        local url=$(curl bashupload.com/db_backup.db --data-binary @$database_file &> ${mk_file})
        url=$(grep -Eo "(http|https)://[a-zA-Z0-9./?=_%:-]*" ${mk_file})
        
        info "COPIES EL SIGUIENTE COMANDO Y PEGALO EN LA TERMINAL:"
        echo -e "\n"
        echo -en "${GREEN} cd ~/FenixManager/backup/ && \n wget $url -O backup_usuarios_$date_.db -q "
        echo -e "\n"
        database_file="${database_file//"$user_folder"/"~"}"
        info "Copia de seguridad creada con exito. ${GREEN}$database_file${WHITE}"
        rm $mk_file
    else
        error 'Fallo la creacion de la copia de seguridad.'
    fi

}

restore_backup () {
    backup_dir="$user_folder/FenixManager/backup"
    backup_files=$(find $backup_dir/*.db  -printf "%f\n")
    
    if [[ $backup_files == 0 ]];then
        error 'No hay copias de seguridad en el directorio.'
        info "Cree una copia de seguridad primero."
        info "Luego guerdela en el directorio ${user_folder}/backup"
        read -p "$(echo -e $MAGENTA'[*] Presione enter para continuar.': )"
        clo
    fi
    if [[ $(sqlite3 $userdb "select count(*) from ssh") -gt 0 ]];then
        error 'La base de datos no esta vacia.'
        info "Elimine todos los usuarios primero."
        return 1
    fi
    local count_=0

    line_separator 60
    printf "〢${WHITE} %-4s ${YELLOW}%-30s${WHITE} %26s\n" 'ID' 'NOMBRE DEL ARCHIVO' "〢"
    line_separator 60
    
    # * LIST FILES
    for file in $backup_files;do
        count_=$(expr $count_ + 1)
        local file_size=$(du -h $backup_dir/$file | awk '{print $1}')
        printf "〢${WHITE}[%-${#id}s] ${YELLOW}%-${#file}s${WHITE} %$((62 -  4 -  - ${#id} - ${#file}))s \n" "${count_}" "${file}" "〢"
        
    done
    
    line_separator 60
    
    while true;do
        read -p "$(echo -e $GREEN'[*] ID de la copia de seguridad a restaurar : ' )" id_backup
        if grep '[Aa-Zz]' <<< $id_backup &> /dev/null || [ -z $id_backup ];then
            error 'Solo valores numericos.'
            continue
        fi
        if [[ $id_backup -le $count_ ]];then
            break
        else
            error 'El id ingresado no existe.'
            continue
        fi

    done
    bak_file=$(find $backup_dir/*.db  -printf "%f\n" | sed -n $id_backup'p')
    info "Restaurando la copia de seguridad '$bak_file' ."
    
    rm $userdb &>/dev/null
    sqlite3 $userdb < $backup_dir/$bak_file
    line_separator 60
    printf "${WHITE}〢 %-30s${YELLOW}%-20s${WHITE}%-10s〢\n" 'USUARIO' 'CONTRASEÑA' 'ESTADO'
    line_separator 60
    for user in $(sqlite3 $userdb "select * from ssh");do
        IFS='|' read -r -a user_array <<< "$user"
        local user="${user_array[0]}"
        local pass="${user_array[2]}"
        local password=$(perl -e 'print crypt($ARGV[0], "password")' $pass)
        printf "${WHITE} %-32s${YELLOW}%-20s" "${user}" "${pass}" && tput sc
        local user_add_stderr=$(useradd -g "ssh_user" --no-create-home --shell /bin/false --gid "ssh_user"  -p "$pass" "$user" 2>&1)
        [ -z "$user_add_stderr" ] && {
            printf "${GREEN}%-10s${WHITE}" "[ OK ]" && tput cud1
        } || {
            printf "${RED}%-10s${WHITE}" "[ $(grep -o "${user}.*" <<< "${user_add_stderr}" | cut -d "'" -f 2 | xargs) ]" && tput cud1
        }
    done

    read -p "$(echo -e $GREEN'[*] Presione enter para continuar.')"
    clo
}

show_acc_ssh_info(){
    local sp="${1:-66}"
    local user_db="/etc/FenixManager/database/usuarios.db"
    local get_total_users=$(sqlite3 "$user_db" "SELECT COUNT(*) FROM ssh" 2> /dev/null || echo "error")
    if [[ "${get_total_users}" == "error" ]];then
        error "La base de datos de usuarios no existe o esta corrupta"
        info "Creando base de datos de usuarios"
        sqlite3 $user_db  'CREATE TABLE ssh (nombre VARCHAR(32) NOT NULL, alias VARCHAR(15), password VARCHAR(20), exp_date DATETIME, max_conn INT NOT NULL );' && {
            info "Base de datos de usuarios creada correctamente"
            read -n 1 -s -r -p "Presiona cualquier tecla para continuar..."
            clear && fenix
        } || {
            error "Error al crear la base de datos de usuarios"
            exit 1
        }

    fi
    local users_=$(sqlite3 "$user_db" "SELECT nombre FROM ssh")
    local online_user=0
    for i in ${users_[@]};do
        local number_session=$(ps auxwww | grep 'sshd:' | awk '{print $1 }' | grep -w -c "$i")
        [[ "${number_session}" -ne '0' ]] &&  ((online_user++))
    done
    local offline_users=$(echo ${get_total_users} - ${online_user} | bc)
    
    [[ -z "${get_total_users}" ]] && get_total_users=0
    
    printf "${WHITE}〢 %13s ${YELLOW}%-${#get_total_users}s ${WHITE} %-10s ${GREEN}%-${#online_user}s ${WHITE}%12s ${RED}%${#offline_users}s${WHITE}%-$(echo 60 - 16 - 35  - ${#get_total_users} - ${#online_user} - ${#offline_users} | bc)s〢\n" "USUARIOS-SSH:" "[${get_total_users}]" "CONECTADOS:" "[${online_user}]" "DESCONECTADOS:" "[${offline_users}]"
}

clo() {
    clear
    line_separator 60
    show_acc_ssh_info
    line_separator 60
    option_menu_ssh
}

check_sqlite3() {
    package_installed "sqlite3"
    if [[ $? -eq 1 ]];then
        error 'No se encontro la herramienta sqlite3.'
        info 'Instalando sqlite3.'
        bar "apt-get install sqlite3 -y"
        if [[ $status -eq 0 ]];then
            info 'Instalacion completada.'
            return 0
        else
            error 'Fallo la instalacion.'
            return 1
        fi
    else
        return 0
    fi
}