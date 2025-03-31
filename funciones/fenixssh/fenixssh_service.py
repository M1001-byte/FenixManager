#!/usr/bin/python3
import json, subprocess, os,socket, time

def port_is_open(port:int) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result

def kill_port(port:int) -> int:
    try:
        os.system(f"kill -9 $(lsof -t -i:{port})")
        return 0
    except:pass

def run_fenixssh(bind_port:int, banner:str, ssh_key:str,action:str="start") -> None:
    binssh='/usr/bin/fenixssh'
    args_parse_to_script = f"{bind_port} '{banner}' '{ssh_key}' "
    tmp_proc = subprocess.Popen([f'{binssh} {args_parse_to_script} &'],shell=True)
    time.sleep(1)

def loadcfg(path:str):
    with open(path, "r") as f:
        data = json.load(f)
    return data

def main(config:str):
    try:os.remove('/var/log/FenixManager/connFenixssh.json')
    except:pass
    data = loadcfg(config)
    
    bind_port  = data['bind_port']
    banner = data['banner']
    ssh_key = data['ssh_key']
    is_open = port_is_open(int(bind_port))
    if is_open == 0:
        kill_port(bind_port)
    run_fenixssh(bind_port, banner, ssh_key)
        
    

if __name__ == "__main__":
    cfg_file="/etc/FenixManager/preferences.bash"
    # ! get user_home from preferences.bash
    with open(cfg_file,"r") as f:
        for line in f:
            if "user_folder=" in line:
                user_dir = line.split("=")[1].strip().replace("'","")
                break

    config_file = f"{user_dir}/FenixManager/fenixssh.json"
    print(f"Config file: {config_file}")
    main(config_file)
