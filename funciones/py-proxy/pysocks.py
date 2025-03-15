from threading import Thread
import sys, socket, select, os, re


def show_info(**kwargs):
    for key, value in kwargs.items():
        value = f"{value[0]}:{value[1]}" if key == "Reenvia_a" else value
        key = key.replace("_", " ")
        print(f"\033[37m\033[33m[*] \033[37m{key.upper()} : \033[32m{value}\033[37m")


replace_payload = (
    lambda payload: payload.replace("[lf]", "\n")
    .replace("[cr]", "\r")
    .replace("[crlf]", "\r\n")
    .encode()
)


class main(object):
    def __init__(self) -> None:

        self.args = self.parse_args()
        self.log_file = ""
        self.regex_ssh_hotkey = re.compile("SSH-2.0-.*")

    def parse_args(self) -> dict:
        args = sys.argv
        desc = f"""Simple proxy forwarding. \033[33mclient\033[37m <--> \033[32mserver_socket\033[37m <--> \033[34mremote_server\033[37m"""
        usage = """Python3 pysocks.py {listen-port} {connect-to} {custom-response}"""
        
        if len(args) == 1:
            print(desc)
            print(usage)
            print("By: https://github.com/M1001-byte/ @tg:Mathiue1001")
            sys.exit(1)
        return args

    def run_the_server(self) -> None:
        try:
            bind_port = int(self.args[1])
            connect_str = self.args[2]
            connect_to = (connect_str.split(":")[0], int(connect_str.split(":")[1]))
            custom_response = replace_payload(self.args[3])
            self.log_file = (
                f"/var/log/FenixManager/pysocks:{bind_port}-{connect_str}.log"
            )

            os.remove(self.log_file) if os.path.exists(self.log_file) else None
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", bind_port))
            sock.listen(0)
            while True:
                client_socket, address = sock.accept()
                client_socket.settimeout(30)
                proxy_socket(client_socket, custom_response, connect_to, address).start()

        except KeyboardInterrupt as er:
            sys.exit(130)
        except Exception as er:
            print(f"[ ERROR ]\033[31m{bind_port}:{connect_str} {er} \033[37m")
            exit(1)


class proxy_socket(Thread, main):
    def __init__(
        self,
        client_soket: tuple,
        custom_response: bytes,
        forwarding_to: tuple,
        addr: tuple,
    ) -> None:

        Thread.__init__(self)

        main.__init__(self)

        self.s = None
        self.conn, self.addr = client_soket, "{}:{}".format(addr[0], addr[1])
        self.connect_to = forwarding_to
        self.buffer_size = 4096
        self.custom_response = custom_response
        self.client_buffer = ""

    def run(self):

        count_packet = 0
        while True:
                payload = self.conn.recv(self.buffer_size)
                if not payload:
                    break
                else:
                    print(f"\033[37m\033[32m[+] \033[37mPayload \033[33m{self.addr}\033[37m {payload}")
                    if count_packet == 0:
                        self.conn.sendall(self.custom_response)
                        count_packet += 1
                    try:
                        ssh_identifier = self.regex_ssh_hotkey.findall(str(payload.decode("utf-8")))
                        self.forward()
                        self.remote.sendall(f"{ssh_identifier[0]}\r\n".encode())
                        self.incoming_connections()
                        break
                    except:
                        pass

    def forward(self):
        try:
            self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.remote.connect(self.connect_to)

        except KeyboardInterrupt:
            sys.exit(130)

        except Exception as er:
            print(f"[ ERROR ] Fallo al conectar con el servidor remoto: \033[33m{self.connect_to}\033[37m")
            self.conn.sendall("HTTP/1.1 503 Service Unavailable\r\n\r\n".encode())
            self.conn.close()
            exit(1)

    def incoming_connections(self):
        err = False
        self.inputs = [self.remote, self.conn]
        while True:
            read, _, err = select.select(self.inputs, [], self.inputs, 3)
            if read:
                for self.s in read:
                    try:
                        data = self.s.recv(self.buffer_size)
                        if len(data) == 0:
                            self.close()
                            break
                        else:
                            if self.s == self.remote:
                                self.conn.sendall(data)
                            else:
                                while data:
                                    byte = self.remote.send(data)
                                    data = data[byte:]
                    except KeyboardInterrupt:
                        sys.exit(130)
                    except Exception as er:
                        # write_to_log(log_file,er)
                        break
            if err:
                break

    def close(self):
        self.inputs = []
        self.remote.close()
        self.conn.close()


def write_to_log(log_file: str, msg: str):
    with open(log_file, "a") as f:
        f.write(f"{msg}\n")


if __name__ == "__main__":

    main().run_the_server()
