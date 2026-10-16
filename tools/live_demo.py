"""Real TCP client/server. Capture separately on a suitable Ethernet interface.
Run server and client on two hosts/VMs or a Linux veth pair. Loopback captures
may have a link type outside the MVP scope; do not relabel them as Ethernet.
"""
import argparse
import socket
import struct
import time


def exact(sock,n):
    buf=b''
    while len(buf)<n:
        part=sock.recv(n-len(buf))
        if not part:
            raise EOFError('Соединение завершено')
        buf+=part
    return buf


def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['server','client'])
    p.add_argument('--host',default='127.0.0.1');p.add_argument('--port',type=int,default=9000)
    args=p.parse_args()
    if args.mode=='server':
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            server.bind((args.host,args.port));server.listen()
            print('Стенд ожидает клиента',flush=True)
            conn,_=server.accept()
            with conn:
                while True:
                    try:
                        header=exact(conn,5)
                        if header[:2]!=b'\xaa\x55':raise ValueError('Неизвестный маркер')
                        body=exact(conn,int.from_bytes(header[3:5],'big'))
                        conn.sendall(header+body)
                    except EOFError:
                        break
    else:
        print('time,action,value',flush=True)
        with socket.create_connection((args.host,args.port)) as conn:
            for value in [21,35,300]:
                payload=b'\xaa\x55\x01\x00\x02'+struct.pack('!H',value)
                print(f'{time.time()},set,{value}',flush=True)
                conn.sendall(payload[:3]);time.sleep(.02);conn.sendall(payload[3:])
                exact(conn,len(payload));time.sleep(.1)
            payload=b'\xaa\x55\x02\x01\x04'+b'Z'*260
            print(f'{time.time()},read_array,260',flush=True)
            conn.sendall(payload);exact(conn,len(payload))


if __name__=='__main__':main()
