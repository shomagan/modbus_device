try:
    import msvcrt
    PLATFORM = "win"
except ImportError:
    PLATFORM = "unix"
    import tty
    import termios
    from select import select
import sys
try:
    from serial.tools.list_ports import comports
except ImportError:
    comports = None
from os import walk
import optparse
import com_transfer
import tcp_ip_transfer
import modbus_parser
import json
import socket
import _thread as thread
DEFAULT_PORT = "COM2"
DEFAULT_BAUDRATE = 115200
DEFAULT_RTS = None
DEFAULT_DTR = None
DESCRIPTION_NAME = "modbus_device_description.json"
UDP_ADV_PORT = 65500
UDP_ADV_MESSAGE = b"{\"pcbs\": \"IIRLS-PCBS-1.0.0\","\
    b"\"name\": \"HVEL\","\
    b"\"serial\": \"HVEL10000\","\
    b"\"model\": \"HVEL1-0123456789ABCD\","\
    b"\"firmware\": \"1.0.0-alpha.1\","\
    b"\"firmwareMetaData\": \"0-g123456789ABCDEF\","\
    b"\"gid\": \"G00000R00\","\
    b"\"mech\": \"HVEL1-MECH-1.0.0\","\
    b"\"icbls\": \"HVEL1-ICBLS-1.0.0\","\
    b"\"ecbls\": \"HVEL1-ECBLS-1.0.0\","\
    b"\"communications\": ["\
        b"{"\
        b"\"type\": \"Modbus/TCP\","\
        b"\"port\": 502,"\
        b"\"unitID\": 3"\
        b"},"\
        b"{"\
        b"\"type\": \"XML/TCP\","\
        b"\"port\": 65550"\
        b"}"\
    b"]"\
b"}"
def get_ch():
    if PLATFORM == "win":
        ch = msvcrt.getch()
        return ch
    elif PLATFORM == "unix":
        fd = sys.stdin.fileno()
        old_setting = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            i, o, e = select([sys.stdin.fileno()], [], [], 5)
            if i:
                ch = sys.stdin.read(1)
            else:
                ch = ""
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_setting)
        return ch
    else:
        return ""


def main(device_description):
    parser = optparse.OptionParser(
            usage="%prog [options] [port [baudrate]]",
            description="modbus_device- A simple program for the Modbus device emulator."
    )
    group = optparse.OptionGroup(parser, "Port settings")
    group.add_option("-p", "--port",
                     dest="port",
                     help="port, a number or a device name. (deprecated option, use parameter instead)",
                     default=DEFAULT_PORT
                     )
    group.add_option("-b", "--baud",
                     dest="baudrate",
                     action="store",
                     type='int',
                     help="set baud rate, default %default",
                     default=DEFAULT_BAUDRATE
                     )
    group.add_option("--parity",
                     dest="parity",
                     action="store",
                     help="set parity, one of [N, E, O, S, M], default=N",
                     default='N'
                     )
    group.add_option("--rtscts",
                     dest="rtscts",
                     action="store_true",
                     help="enable RTS/CTS flow control (default off)",
                     default=False
                     )
    group.add_option("--xonxoff",
                     dest="xonxoff",
                     action="store_true",
                     help="enable software flow control (default off)",
                     default=False
                     )
    group.add_option("--rts",
                     dest="rts_state",
                     action="store",
                     type='int',
                     help="set initial RTS line state (possible values: 0, 1)",
                     default=DEFAULT_RTS
                     )
    group.add_option("--dtr",
                     dest="dtr_state",
                     action="store",
                     type='int',
                     help="set initial DTR line state (possible values: 0, 1)",
                     default=DEFAULT_DTR
                     )
    parser.add_option_group(group)
    (options, args) = parser.parse_args()
    options.parity = options.parity.upper()
    if options.parity not in 'NEOSM':
        parser.error("invalid parity")
    print(options)
    print(PLATFORM)
    serial_port = com_transfer.com_init(options.port, options.baudrate,
                                        options.parity, options.rtscts, options.xonxoff)
    ip_socket = tcp_ip_transfer.tcp_ip_init(device_description["tcp_port"])
    mdb_device = modbus_parser.ModbusHandler(device_description)
    print(mdb_device.spaces)
    if com_transfer.serial_is_open:
        com_transfer.com_start_list(serial_port, mdb_device)
    if ip_socket:
        tcp_ip_transfer.tcp_ip_start_list(ip_socket, mdb_device)
    if device_description["udp_adv"]:
        print("start udp advertisment")
        udp_port_self = 65500
        buffer_size = 1512
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Enable broadcasting mode
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", udp_port_self))
        thread.start_new_thread(udp_list, (sock,))
    packet_num = 0
    while 1:
        q = get_ch()
        if q:
          print(ord(q))
          if ord(q) == 113:   #q
              com_transfer.close(serial_port)
              tcp_ip_transfer.close(ip_socket)
              sys.exit(1)
          if mdb_device.packet_receive_num != packet_num:
              print(mdb_device.packet_receive_num)


def udp_list(sock):
    print("start listening")
    packet_number = 0
    while 1:
        data, address = sock.recvfrom(1024)
        packet_number += 1
        if data != b"master confirmation":
            sock.sendto(UDP_ADV_MESSAGE, address)


if __name__ == '__main__':
    '''request modbus packet on com port or tcp connect
      options:
        -p port
        -b baud rate
    '''
    for (dirpath, dirnames, filenames) in walk(".."):
        for i in range(len(filenames)):
            if(DESCRIPTION_NAME == filenames[i]):
                file_description = open(filenames[i], "r")
                device_description = json.loads(file_description.read())
                print(device_description)
                device_description["spaces_num"] = len(device_description["spaces"])
                print("spaces num - {}".format(device_description["spaces_num"]))
                main(device_description)
    print("did't find file description - {}".format(DESCRIPTION_NAME))
