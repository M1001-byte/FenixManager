# -*- coding: utf-8 -*-
import socket
import threading
import select
import sys
import time


# este script solo es una modificacion del script que usaban los brasucas en su adm.
# Yo solo lo traslade a python3 y elimine cosas inecesarioas.
# BY: tg://Mathiue1001

replace_payload = (
    lambda payload: payload.replace("[lf]", "\n")
    .replace("[cr]", "\r")
    .replace("[crlf]", "\r\n")
    .encode()
)


args = sys.argv
desc = f"""Simple proxy forwarding. \033[33mclient\033[37m <--> \033[32mserver_socket\033[37m <--> \033[34mremote_server\033[37m"""
usage = """Python3 pysocks.py {listen-port} {connect-to} {custom-response}"""

if len(args) == 1:
    print(desc)
    print(usage)
    print("By: https://github.com/M1001-byte/ @tg:Mathiue1001")
    sys.exit(1)

BIND_PORT = int(args[1])
connect_str = args[2]
CONNECT_TO = (connect_str.split(":")[0], int(connect_str.split(":")[1]))
CUSTOM_RESPONSE = replace_payload(args[3])

BUFLEN = 4096 * 4
TIMEOUT = 60

class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(5)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    print("New Connection from:",addr)
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def addConn(self, conn):
        with self.threadsLock:
            if self.running:
                self.threads.append(conn)

    def removeConn(self, conn):
        with self.threadsLock:
            if conn in self.threads:
                self.threads.remove(conn)

    def close(self):
        self.running = False
        with self.threadsLock:
            for c in list(self.threads):
                c.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server):
        super().__init__()
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = b''
        self.server = server
        self.target = None

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed and self.target:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            self.method_CONNECT()
            
        except Exception as e:
            print('error:',str(e))
        finally:
            self.close()
            self.server.removeConn(self)

    def connect_target(self):
        try:
            self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.targetClosed = False
            self.target.connect(CONNECT_TO)
        except Exception as e:
            print(f"Error al conectar con {CONNECT_TO} - {e}")

    def method_CONNECT(self):
        try:
            self.connect_target()
            self.doCONNECT()
            self.client.sendall(CUSTOM_RESPONSE)
            self.client_buffer = b''
        except Exception as er :
            print(er)

    def doCONNECT(self):
        
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            recv, _, err = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
                    try:
                        data = in_.recv(BUFLEN)
                        if data:
                            if in_ is self.target:
                                self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]
                            count = 0
                        else:
                            break
                    except:
                        error = True
                        break
            if count == TIMEOUT or error:
                break

def main():
    server = Server('0.0.0.0', BIND_PORT)
    server.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        server.close()

if __name__ == '__main__':
    main()
