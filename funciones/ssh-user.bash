#!/usr/bin/bash

current_dir=$(pwd)
userdb='/etc/FenixManager/database/usuarios.db'

source "/etc/FenixManager/funciones/funciones.bash"
source "/etc/FenixManager/funciones/color.bash"

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
                read -p "$(echo -e $YELLOW"[*] Contraseña para $user $str: " )" passwd
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
            
            read -p "$(echo -e $GREEN'[*] Cantidad de dias para expirar : ' )" date_exp
            
            if [[ -z "$date_exp" ]];then
                info "Valor incorrecto, se asignara una fecha de expiracion de 1 dia."
                date_exp=1
            fi
            
            # ! crear temp user
            [[ "${date_exp}" =~ ^- ]] && {
                create_temp_user
            } || {
                if [ -z "${date_exp}" ] || [ ! grep -E '^[0-9]+$' <<< "${date_exp}" 2>/dev/null ] || [ "${date_exp}" == 0 ];then
                    info 'El valor no es correcto.De forma predeterminada, se le asignara un (1) dia.'
                    fecha_final=$(date -d "1 days" +%Y-%m-%d) 
                else
                    fecha_final=$(date -d "$date_exp days" +%Y-%m-%d 2>/dev/null)
                fi
                fecha_final=($fecha_final + $(date +'%T'))
            }
            read -p "$(echo -e $RED'[*] Cantidad maxima de conexiones : ' )" max_connections
            if [ -z $max_connections ] || [ ! grep -E '^[0-9]+$' <<< $max_connections &>/dev/null ] || [ $max_connections = 0 ];then
                info 'El valor no es correcto.De forma predeterminada, se le asignara un maximo de una (1) conexion.'
                max_connections=1
            fi

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

    if [[ ${columns} -le 78 ]];then
        line_separator 74
        printf "${WHITE}〢%-2s ${RED}%-25s ${RED}%-15s ${BLUE}%-20s ${WHITE}%-9s〢\n" 'ID' 'NOMBRE' 'ALIAS' 'CONTRASEÑA' 'CADUCA'
        line_separator 74
    else
        [[ ${columns} -ge 100 ]] && {
            line_separator 94
            printf "${WHITE}〢 %-2s ${RED}%-32s ${RED}%-15s ${BLUE}%-20s ${MAGENTA}%-10s ${WHITE}%-12s〢\n" 'ID' 'NOMBRE' 'ALIAS' 'CONTRASEÑA' 'EXPIRACION' 'CONEXIONES'
            line_separator 94
        } || {
            line_separator 86
            printf "${WHITE}〢 %-2s ${RED}%-32s ${RED}%-15s ${BLUE}%-20s ${MAGENTA}%-10s ${WHITE}%-10s 〢\n" 'ID' 'NOMBRE' 'ALIAS' 'CONTRASEÑA' 'EXPIRACION' 'CONEXIONES'
            line_separator 86
        }
    fi
    
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
        
        if [[ ! "${number_session}" -eq 0 ]];then
            ((users_connected++))
        fi

        if [[ -z ${var_val[2]} ]];then
            alias_='-'
        else
            alias_=${var_val[2]}
        fi

        [[ ${#user} -gt 25 && ${columns} -lt 100 ]] && {
            # ! (...)
            user="${user:0:20}(...)"
        }
        
        password=${var_val[3]}
        exp=${var_val[4]}
        conn=$number_session"/"${var_val[5]}
        if [[ $columns -le 78 ]];then
            printf "${WHITE}〢%-2s${RED}%-25s ${RED}%-15s${BLUE}%-20s ${WHITE}%-6s\n" $id $user $alias_ $password $exp 
        elif [[ ${columns} -ge 100 ]];then
            printf "${WHITE}〢 %-2s ${RED}%-32s ${RED}%-15s ${BLUE}%-20s ${MAGENTA}%-10s ${WHITE}%-11s〢\n" $id $user $alias_ $password $exp $conn
        else
            printf "${WHITE}〢 %-2s ${RED}%-25s ${RED}%-15s ${BLUE}%-20s ${MAGENTA}%-10s ${WHITE}%-10s〢\n" $id $user $alias_ $password $exp $conn
        fi
    done
    local users_disconnected=$(($total_users - $users_connected))
    if [[ $columns -le 78 ]];then
        line_separator 74
        local length_=$(echo 58 - 15 - 15 - 15 - ${#total_users} - ${#users_connected} - ${#users_disconnected} | bc)
        printf "${WHITE}〢 %15s ${YELLOW}%-${#total_users}s ${WHITE}%15s ${GREEN}%-${#users_connected}s ${WHITE}%15s ${RED}%-${#users_disconnected}s ${WHITE}%${length_}s\n" "TOTAL:" "[ ${total_users} ]" "CONECTADOS:" "[ ${users_connected} ]" "DESCONECTADOS:" "[ ${users_disconnected} ]" '〢'
        line_separator 74
    elif [[ ${columns} -ge 100 ]];then
        local tcp_conn=$(ss -t | grep ssh -c)
        line_separator 94
        local length_=$(echo 80 - 60 - ${#total_users} - ${#users_connected} - ${#users_disconnected} - ${#tcp_conn} - 7| bc)
        printf "${WHITE}〢 %15s ${YELLOW}%-${#total_users}s ${WHITE}%15s ${GREEN}%-${#users_connected}s ${WHITE}%15s ${RED}%-${#users_disconnected}s ${WHITE} %-15s ${GREEN}%-${#tcp_conn}s ${WHITE}%${length_}s\n" "TOTAL:" "[ ${total_users} ]" "CONECTADOS:" "[ ${users_connected} ]" "DESCONECTADOS:" "[ ${users_disconnected} ]" 'CONEXIONES-TCP:' "[ ${tcp_conn} ]" '〢'
        line_separator 94
    else
        line_separator 86
        local length_=$(echo 72 - 15 - 15 - 15 - ${#total_users} - ${#users_connected} - ${#users_disconnected} | bc)
        printf "${WHITE}〢 %15s ${YELLOW}%-${#total_users}s ${WHITE}%15s ${GREEN}%-${#users_connected}s ${WHITE}%15s ${RED}%-${#users_disconnected}s ${WHITE}%${length_}s\n" "TOTAL:" "[ ${total_users} ]" "CONECTADOS:" "[ ${users_connected} ]" "DESCONECTADOS:" "[ ${users_disconnected} ]" '〢'
        line_separator 86
    fi

}

option_menu_ssh() {
    option_color '1' 'AGREGAR USUARIO'
    option_color '2' 'ELIMINAR USUARIO'
    option_color '3' 'EDITAR USURIO'  
    option_color '4' 'CREAR UN BACKUP DE LA BASE DE DATOS'
    option_color '5' 'RESTAURAR BACKUP DE LA BASE DE DATOS'
    option_color '6' "${RED}ELIMINAR TODOS LOS USUARIOS"
    option_color 'E' 'SALIR'
    option_color 'M' 'MENU PRINCIPAL'
    
    while true;do
        prompt=$(date "+%x %X")
        read -p "$(echo -e "${WHITE}[$BBLUE${prompt}${WHITE}")] : " option
        case $option in
            1 )
                create_ssh_user_input
                clo
                ;;
            2 )
                delete_user
                break
                ;;
            3 )
                edit_user
                break
                ;;
            4 )
                backup_user
                break
                ;;
            5 )
                restore_backup
                break
                ;;
            6 )
                delete_all_users
                ;;
            e | E | q | Q )
                exit 0
                ;;
            m | M )
                fenix
                ;;
                
            esac
        done
}

delete_user () {
    read -p "$(echo -e $WHITE'[*] Ingrese el id del usuario a eliminar : ' )" id_user
    user_name=$(sqlite3 $userdb "select rowid,nombre from ssh where rowid = $id_user" | awk '{split($0,a,"|");print a[2]}')
    
    grep -q $user_name /etc/passwd
    if [[ $? != 0 ]];then
        error 'El usuario esta presente en la base de datos,pero no en el sistema.'
        sqlite3 $userdb "delete from ssh where nombre = '$user_name'"
        if [[ $status == 0 ]];then
            info 'Usuario eliminado de la base de datos'
        else
            error 'Fallo la eliminacion del usuario de la base de datos.'
        fi
        read -p "$(echo -e $WHITE'[*] Presione enter para continuar... ' )"
    else
        pkill -u $user_name
        sqlite3 $userdb "delete from ssh where nombre = '$user_name'"
        userdel $user_name
        info  "El Usuario ${RED}${user_name}${WHITE} eliminado con exito."
    fi
    clo
}

delete_all_users() {
    read -p "$(echo -e $RED'[*] Esta seguro de eliminar todos los usuarios (S)i (N)o : ' )" confirm
    case $confirm in
        S | s | y | y )
            info "Eliminando todos los usuarios.Esta accion no se puede deshacer."
            read -p "$(echo -e $MAGENTA'[*] Desea respaldar los usuarios (S)i (N)o': )" bak
            case $bak in
                S | s | y | Y )
                    backup_user
                esac
            
            for user in $(sqlite $userdb "select nombre from ssh" &>/dev/null);do
                userdel $user &>/dev/null
            done
            sqlite3 $userdb "delete from ssh"
            info "Todos los usuarios han sido eliminados."
            read -p "$(echo -e $MAGENTA'[*] Presione enter para continuar.': )"
            clo
            ;;
        m | M )
            fenix
            ;;
        esac
}

edit_user () {
    all_ids=$(sqlite3 $userdb "select rowid,nombre from ssh" | awk '{split($0,a,"|");print a[1]}')
    
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
        if [[ ${#user} -gt 32 ]];then
            error 'El nombre de usuario no puede tener mas de 32 caracteres.'
            continue
        fi
        if [[ -z $new_name ]];then
            new_name=$name
            break
        else
            if ! check_user_exist $new_name;then
                break
            fi
        fi
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
    done
    
    exp_date_default=$(sqlite3 $userdb "select exp_date from ssh where rowid = $id_user")
    read -p "$(echo -e $RED'[*] Cantidad de dias a expirar : ' )" exp_date
    if  [[ -z $exp_date ]];then
        exp_date=$exp_date_default
    else
        exp_date=$(date -d "$exp_date days" +%Y-%m-%d)
    fi
    
    max_conn_default=$(sqlite3 $userdb "select max_conn from ssh where rowid = $id_user")
    read -p "$(echo -e $YELLOW'[*] Cantidad de conexiones permitidas : ' )" max_conn
    
    if [[ -z $max_conn ]];then
        max_conn=$max_conn_default
    fi

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
                echo -e "\\033[1;32m[*] El Usuario $new_name (anteriormente $name) editado con exito.\\033[m"
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
        
        echo -e "${YELLOW}〢 PARA RESTAURAR EL BACKUP,SIMPLEMENTE COPIE Y PEGUE EL SIGUIENTE COMANDO:〢"
        echo ""
        echo -e "${GREEN} cd ~/FenixManager/backup/ && wget $url -O backup_usuarios_$date_.db -q --show-progress "
        echo ""
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
        info "Cree una copia de seguridad primero.Y luego guerdela en el directorio ${user_folder}/backup"
        read -p "$(echo -e $MAGENTA'[*] Presione enter para continuar.': )"
        clo
    fi
    
    count_=0

    [[ ${columns} -le 78 ]] && {
        line_separator 73
        printf "〢${WHITE} %-2s ${YELLOW}%-38s${WHITE} %33s\n" 'ID' 'NOMBRE DEL ARCHIVO' "〢"
    } || {
        line_separator 79
        printf "〢${WHITE} %-2s   ${YELLOW}%-38s${WHITE} %39s\n" 'ID' 'NOMBRE DEL ARCHIVO' "〢"
    }
    for file in $backup_files;do
        count_=$(expr $count_ + 1)
        [[ ${columns} -le 78 ]] && {
            printf "〢${WHITE} [%${#count_}s] ${YELLOW}%-38s${WHITE} %32s\n" "${count_}" "${file}" "〢"
        } || {
            printf "〢${WHITE} [%${#count_}s]  ${YELLOW}%-38s${WHITE} %39s\n" "${count_}" "${file}" "〢"
        }
    done
    [[ ${columns} -le 78 ]] && line_separator 73 || line_separator 79
    
    while true;do
        read -p "$(echo -e $GREEN'[*] Seleccione el ID de la copia de seguridad a restaurar : ' )" id_backup
        if grep '[Aa-Zz]' <<< $id_backup > /dev/null;then
            error 'Solo valores numericos.'
            continue
        fi
        if [[ -z $id_backup ]];then
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
    info 'Esta operacion,sobreescribira los datos actuales de los usuarios.'
    read -p "$(echo -e $GREEN'[*] Desea continuar (S)i (N)o : ' )" confirm
    case $confirm in
        s | S )
            rm $userdb &>/dev/null
            sqlite3 $userdb < $backup_dir/$bak_file
            if [[ $status -eq 0 ]];then
                info 'La copia de seguridad se ha restaurado con exito.'
            else
                error 'Fallo la restauracion de la copia de seguridad.'
            fi
            read -p "$(echo -e $GREEN'[*] Presione enter para continuar.': )"
            clo
            ;;
        n | N )
            clo
            ;;
        esac
}

clo() {
    clear
    list_user
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
