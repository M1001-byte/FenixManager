#!/usr/bin/python3
"""
SIMPLE PYTHON PROXY FORWARDER

https://github.com/m1001-byte/
https://github.com/m1001-byte/FenixManager

"""

from threading import Thread
import sys, socket, select, argparse, os
from colorama import Fore

def show_info(**kwargs):
    for key,value in kwargs.items():
        value = f"{value[0]}:{value[1]}" if key == 'Reenvia_a' else value
        key = key.replace("_"," ")
        print(f"{Fore.WHITE}{Fore.YELLOW}[*] {key.upper()}{Fore.WHITE} : {Fore.GREEN}{value}{Fore.WHITE}")

replace_payload = lambda payload: payload.replace("[lf]","\n").replace("[cr]","\r").replace("[crlf]","\r\n").encode()


class proxy_socket(Thread):
    def __init__(self,client_soket:tuple,custom_response:bytes,forwarding_to:tuple,addr:tuple) -> None:
        Thread.__init__(self)
        self.s = None
        self.conn,self.addr = client_soket,"{}:{}".format(addr[0],addr[1])
        self.connect_to = forwarding_to
        self.buffer_size = 4096
        self.custom_response = custom_response

    def run(self):
        self.forward()
        self.incoming_connections()
    
    def forward(self):
        try:
            self.remote = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self.remote.connect_ex (self.connect_to)
        except KeyboardInterrupt: sys.exit(130)
        except Exception as er:
            print(f"[ ERROR ] Fallo al conectar con el servidor remoto: {Fore.YELLOW}{self.connect_to}{Fore.WHITE}")
            exit(1)
    
    def incoming_connections(self):
        self.inputs = [self.remote,self.conn]
        
        if self.custom_response != b"None":
            payload=self.conn.recv(self.buffer_size)
            self.conn.sendall(self.custom_response)

        while self.inputs:
            try:
                read, _, _ = select.select(self.inputs, [],[])
            
                for self.s in read:
                    self.data = self.s.recv(self.buffer_size)
                    if len(self.data) == 0:
                        self.close()
                        break
                        
                    else:
                        if self.s == self.remote:
                            self.conn.sendall(self.data)
                        else:
                            self.remote.sendall(self.data)
            except KeyboardInterrupt:
                sys.exit(130)
            except Exception as er:
                write_to_log(log_file,er)
                self.close()
                break
                        
    def close(self):
        self.inputs = []
        self.remote.close()
        self.conn.close()


def parse_args() -> dict:
    desc=f"""Simple proxy forwarding. {Fore.YELLOW}client {Fore.WHITE} <--> {Fore.GREEN}server_socket{Fore.WHITE} <--> {Fore.BLUE}remote_server{Fore.WHITE}"""
    parser = parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-p","--port",type=int,help="Puerto de escucha.(9090)",default=9090)
    parser.add_argument("-c","--connect",type=str,help="Direccion donde redireccionara todo el trafico. (127.0.0.1:22)",default="127.0.0.1:22")
    parser.add_argument("--custom-response",help="Respuesta personalizada para enviar al cliente cuando se establece la conexion. ( None )",default="None",type=str)

    args = parser.parse_args()
    return args

def run_the_server():
    try:
        args = parse_args()
        bind_port = args.port
        connect_str = args.connect
        connect_to = (connect_str.split(":")[0],int(connect_str.split(":")[1]))
        custom_response = replace_payload(args.custom_response)
        global log_file

        log_file = f"/var/log/FenixManager/pysocks:{bind_port}-{connect_str}.log"
        os.remove(log_file) if os.path.exists(log_file) else None

        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.bind(("0.0.0.0",bind_port))
        sock.listen(0)
        
        while True:
            client_socket,address = sock.accept()
            proxy_socket(client_socket,custom_response,connect_to,address).start()

    except KeyboardInterrupt as er: sys.exit(130)
    except Exception as er:
        print(f"[ ERROR ]{Fore.RED}{bind_port}:{connect_str} {er} {Fore.WHITE}")
        exit(1)

def write_to_log(log_file:str,msg:str):
    with open(log_file,"a") as f:
        f.write(f"{msg}\n")

if __name__ == "__main__":
    run_the_server()
