#!/usr/bin/python3
import configparser, subprocess, time, sys, os, socket

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
def run_proxy_server(bind_port:int, connect_to:str, custom_response:str,action:str="start") -> None:
    proxy_file='/etc/FenixManager/funciones/py-proxy/pysocks.py'
    args_parse_to_script = f"{bind_port} '{connect_to}' '{custom_response}' "
    tmp_proc = subprocess.Popen([f'python3 {proxy_file} {args_parse_to_script} &'],shell=True)
    time.sleep(1)
    #return tmp_proc.pid

show_info = lambda index,accept,connect : print(f"Proxy [#{index}]: 0.0.0.0:{accept} -> {connect}")

def main(config:str):
    parser = configparser.ConfigParser()
    parser.read(config)
    
    for index,section in enumerate(parser.sections()):
        try:
            bind_port = parser.get(section, 'accept')
            connect_to = parser.get(section, 'connect')
            custom_response = parser.get(section, 'custom_response')
        except Exception as er:
            print(er)
        #log_file = f"/var/log/FenixManager/pysocks:{bind_port}-{connect_to}.log"
        
        is_open = port_is_open(int(bind_port))
        if reload_:
            if is_open == 0:
                continue
            #print(f"Log File [#{index}] : {log_file}")
            show_info(index,bind_port,connect_to)
            run_proxy_server(bind_port, connect_to, custom_response)
        else:
            show_info(index,bind_port,connect_to)
            run_proxy_server(bind_port, connect_to, custom_response)


if __name__ == "__main__":
    reload_ = False
    if len(sys.argv) == 2:
        if sys.argv[1] == "reload":
            reload_ = True
    cfg_file="/etc/FenixManager/preferences.bash"
    # ! get user_home from preferences.bash
    with open(cfg_file,"r") as f:
        for line in f:
            if "user_folder=" in line:
                user_dir = line.split("=")[1].strip().replace("'","")
                break

    config_file = f"{user_dir}/FenixManager/py-socks.conf"
    print(f"Config file: {config_file}")
    main(config_file)
