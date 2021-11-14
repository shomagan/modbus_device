#!/c/Python33/ python
import sys
import time
import socket
import _thread as thread
BUFFER_SIZE = 1024
tcp_ip_is_open = 0
receive_timer = 0
receive_byte_num = 0



def get_network_ip():
    print("Getting private IP")
    names = socket.gethostname()
    print("names " + names)
    ip = socket.gethostbyname(socket.gethostname())
    print("IP: " + ip)
    return ip


def tcp_ip_init(port):
    global tcp_ip_is_open
    self_ip = get_network_ip()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((self_ip, port))
    s.listen(1)
    print(s)
    tcp_ip_is_open = 1
    return s


def tcp_ip_start_list(socket, device):
    thread.start_new_thread(tcp_ip_list, (socket, device))


def tcp_ip_list(socket_s, device):
    global receive_timer
    global receive_byte_num
    global conn
    receive_byte_num = 0
    packet_num = 0
    receive_timer = time.time()
    conn, addr = socket_s.accept()
    print("start_tcp_ip_listing")
    while 1:
        try:
            data = conn.recv(BUFFER_SIZE)
            if data:
                receive_byte_num = len(data)
                packet_num += 1
                if device.receive_tcp_packet(data, len(data)):
                    receive_buff_temp = [device.answer_packet[i] for i in range(device.answer_packet_size)]
                    conn.send(bytearray(receive_buff_temp))
            if not data:
                print("close tcp connection")
                conn.close()
                conn, addr = socket_s.accept()
        except socket.error:
            print("close tcp connection by error")
            conn.close()
            conn, addr = socket_s.accept()


def close(socket):
    socket.close()