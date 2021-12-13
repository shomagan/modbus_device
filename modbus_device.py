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
import json
import socket
import time
import logging
import _thread as thread

TCPIP_BUFFER_SIZE = 1024
SERIAL_MAX_RECEIVE_BYTE = 255
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
ILLEGAL_FUNCTION = 0x01
ILLEGAL_DATA_ADDRESS = 0x02
ILLEGAL_DATA_VALUE = 0x03
SLAVE_DEVICE_FAILURE = 0x04
ACKNOWLEDGE = 0x05
SLAVE_DEVICE_BUSY = 0x06
NEGATIVE_ACKNOWLEDGE = 0x07
MEMORY_PARITY_ERROR = 0x08
GATEWAY_PATH_UNAVAILABLE = 0x0A
GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND = 0x0B


def serial_listening_thread(device):
    serial_receive_byte_num = 0
    packet_num = 0
    print("start_serial_listening_threading")
    serial_receive_timer = time.time()
    while 1:
        if (time.time() > (serial_receive_timer+0.02)) & (serial_receive_byte_num!=0):
            if device.receive_rtu_packet(device.serial_receive_buff, serial_receive_byte_num):
                device.send_packet(device.serial_port_list, device.answer_packet, device.answer_packet_size)
            else:
                print('error_packet',device.serial_receive_buff[0:serial_receive_byte_num])
            serial_receive_byte_num = 0
            packet_num += 1
        device.serial_port_list.timeout = 0.03
        receive_char = device.serial_port_list.read(1)
        if receive_char:
            serial_receive_timer = time.time()
            if serial_receive_byte_num >= SERIAL_MAX_RECEIVE_BYTE:
                print('error max_packet_size',device.serial_receive_buff)
                serial_receive_byte_num =0
            device.serial_receive_buff[serial_receive_byte_num] = ord(receive_char)
            serial_receive_byte_num += 1


def tcp_ip_listening(device):
    packet_num = 0
    conn, addr = device.modbus_socket.accept()
    print("start_tcp_ip_listeninging")
    while 1:
        try:
            data = conn.recv(TCPIP_BUFFER_SIZE)
            if data:
                packet_num += 1
                if device.receive_tcp_packet(data, len(data)):
                    receive_buff_temp = [device.answer_packet[i] for i in range(device.answer_packet_size)]
                    logging.info('send: {}'.format(receive_buff_temp))
                    print(receive_buff_temp)
                    conn.send(bytearray(receive_buff_temp))
            if not data:
                print("close tcp connection")
                conn.close()
                conn, addr = device.modbus_socket.accept()
        except socket.error:
            print("close tcp connection by error")
            conn.close()
            conn, addr = device.modbus_socket.accept()


def udp_listening(sock):
    print("start listening")
    packet_number = 0
    while 1:
        data, address = sock.recvfrom(1024)
        packet_number += 1
        if data != b"master confirmation":
            sock.sendto(UDP_ADV_MESSAGE, address)


class TCPConnection(object):
    tcp_ip_is_open = 0

    def __init__(self, port):
        self.tcp_ip_is_open = 0
        self.receive_timer = 0
        self.receive_byte_num = 0
        self.self_ip = self.get_network_ip()
        self.modbus_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.modbus_socket.bind((self.self_ip, port))
        self.modbus_socket.listen(1)
        print(self.modbus_socket)
        self.tcp_ip_is_open = 1
        self.tcp_ip_start_list()

    def __del__(self):
        if self.tcp_ip_is_open:
            self.modbus_socket.close()

    @staticmethod
    def get_network_ip():
        print("Getting private IP")
        names = socket.gethostname()
        print("names " + names)
        ip = socket.gethostbyname(socket.gethostname())
        print("IP: " + ip)
        return ip

    def tcp_ip_start_list(self):
        thread.start_new_thread(tcp_ip_listening, (self,))


class SerialConnection(object):
    serial_is_open = 0

    def __init__(self, port, baudrate, parity, rtscts, xonxoff):
        self.serial_is_open = 0
        self.serial_receive_timer = 0
        self.serial_receive_byte_num = 0
        self.serial_receive_buff = [0 for x in range(SERIAL_MAX_RECEIVE_BYTE)]
        try:
            import serial
        except ImportError:
            self.serial_is_open = 0
            print("could not import\n")
            return self.serial_is_open
        try:
            try:
                self.serial_port = serial.serial_for_url(port, baudrate, parity=parity,
                                                    rtscts=rtscts, xonxoff=xonxoff, timeout=1)
            except AttributeError:
                # happens when the installed pyserial is older than 2.5. use the
                # Serial class directly then.
                self.serial_port = serial.Serial(port, baudrate, parity=parity,
                                            rtscts=rtscts, xonxoff=xonxoff, timeout=1)
            print(self.serial_port.name)  # check which port was really used
            self.serial_is_open = 1
            sys.stderr.write('--- modbus device on %s: %d,%s,%s,%s ---\n' % (
                self.serial_port.portstr,
                self.serial_port.baudrate,
                self.serial_port.bytesize,
                self.serial_port.parity,
                self.serial_port.stopbits,
            ))
        except serial.SerialException as e:
            self.serial_is_open = 0
            print("could not open port \n")
        if self.serial_is_open:
            self.com_start_list()
            return self.serial_port
        else:
            return self.serial_is_open

    def __del__(self):
        if self.serial_is_open:
            self.serial_port.close()

    def com_start_list(self):
        thread.start_new_thread(serial_listening_thread, (self,))

    def send_packet(self, buff, size):
        packet = buff[0:size]
        print('-<---<.>--->-',buff[0:size])
        self.serial_port.write(packet)
        print(time.asctime())


class ModbusDevice(SerialConnection, TCPConnection):

    def __init__(self, device_description, serial_port=DEFAULT_PORT, serial_baudrate=DEFAULT_BAUDRATE,
                 serial_parity='N', serial_rtscts=False, serial_xonxoff=False):
        if device_description["modbus_tcp"]:
            TCPConnection.__init__(self, device_description["tcp_port"])
        if device_description["modbus_rtu"]:
            SerialConnection.__init__(self, serial_port, serial_baudrate, serial_parity, serial_rtscts, serial_xonxoff)
        logging.basicConfig(filename='packet.log', level=logging.DEBUG)
        print("add modbus device with address", device_description["address"])
        self.modbus_address = device_description["address"]
        self.packet_receive_num = 0
        self.answer_packet = [0 for x in range(0, 1024)]
        self.answer_packet_size = 0
        self.size_answer_packet = 0
        self.spaces = []
        for i in range(device_description["spaces_num"]):
            space = {}
            buffer = [i for i in range(device_description["spaces"][i]["registers_num"])]
            space["buffer"] = buffer
            space.update(device_description["spaces"][i])
            for j in range(len(device_description["spaces"][i]["init_buffer"])):
                space["buffer"][j] = device_description["spaces"][i]["init_buffer"][j]
            print("space inited {}".format(space["buffer"]))
            self.spaces.append(space)

    def __del__(self):
        print("dlt handler")

    def receive_rtu_packet(self, buff, num_byte, crc_check=1):
        if num_byte > 4:
            print(num_byte)
            if crc_check == 0 or \
               self.calc_crc(buff, num_byte) == (buff[num_byte - 2] + (buff[num_byte - 1] << 8)):
                if buff[0] == self.modbus_address:
                    self.packet_receive_num += 1
                    print(time.asctime(),'good packet number',self.packet_receive_num)
                    size = 0
                    if buff[1] == 3:
                        logging.info('recv - modbus funct 3: {}'.format([int(buff[i]) for i in range(len(buff))]))
                        size = self.modbus_func_3(buff, num_byte)
                        return size
                    if buff[1] == 4:
                        logging.info('recv - modbus funct 4: {}'.format([int(buff[i]) for i in range(len(buff))]))
                        size = self.modbus_func_4(buff, num_byte)
                        return size
                    elif buff[1] == 6:
                        logging.info('recv - modbus funct 6: {}'.format([int(buff[i]) for i in range(len(buff))]))
                        size = self.modbus_func_6(buff, num_byte)
                        return size
                    elif buff[1] == 16:
                        logging.info('recv - modbus funct 16: {}'.format([int(buff[i]) for i in range(len(buff))]))
                        size = self.modbus_func_16(buff, num_byte)
                        return size

                    else:
                        return 0
            else:
                return 0
        else:
            return 0

    def reg_address_in_space(self, reg_address, regs_num):
        j = 0
        for i in self.spaces:
            if (reg_address >= i["start_address"]) and ((reg_address + regs_num) <= (i["start_address"]+i["registers_num"])):
                return j, reg_address - i["start_address"]
            j += 1
        return -1, -1

    def receive_tcp_packet(self, buff, num_byte):
        if num_byte > 10:
            print(buff[0:num_byte])
            size = self.receive_rtu_packet(buff[6:], num_byte,crc_check=0)
            if size:
                for i in range(0, 6):
                    self.answer_packet.insert(i,buff[i])
                self.answer_packet_size -=2 #without crc
                self.answer_packet_size +=6 #add header
                return size
            else:
                return 0
        else:
            return 0

    @staticmethod
    def calc_crc(pck, packet_length):
        """CRC16 for modbus"""
        crc = 0xFFFF
        i = 0
        length = packet_length - 2
        while i < length:
            crc ^= pck[i]
            i += 1
            j = 0
            while j < 8:
                j += 1
                if (crc & 0x0001) == 1:
                    crc = ((crc >> 1) & 0xFFFF) ^ 0xA001
                else:
                    crc >>= 1
        return crc

    def modbus_func_3(self, packet, length):
        '''read holding registers'''
        self.answer_packet_size = 0
        start_address = (packet[2] << 8) + (packet[3])
        num_regs = (packet[4] << 8) + (packet[5])
        space_num, position = self.reg_address_in_space(start_address, num_regs)
        print(self.spaces[space_num]["buffer"])
        if (num_regs < 1) or (num_regs > 125) or (space_num<0):
            logging.error("f16 illegal space for address - {} size - {}".format(start_address, num_regs))
            self.size_answer_packet = 5
            self.answer_packet[0] = packet[0]
            self.answer_packet[1] = packet[1]|0x80
            self.answer_packet[2] = 0x03
            crc = self.calc_crc(self.answer_packet, 5)
            self.answer_packet[3] = crc << 8 & 0xff
            self.answer_packet[4] = crc & 0xff
            self.answer_packet_size = 5
        else:
            self.answer_packet[0] = packet[0]
            self.answer_packet[1] = packet[1]
            self.answer_packet[2] = num_regs*2
            for i in range(num_regs):
                self.answer_packet[i*2 + 3] = (self.spaces[space_num]["buffer"][i + position] >> 8) & 0xff
                self.answer_packet[i*2 + 4] = (self.spaces[space_num]["buffer"][i + position]) & 0xff
            print(self.answer_packet[4:num_regs*2])
            print(self.spaces[space_num]["buffer"])
            crc = self.calc_crc(self.answer_packet, num_regs*2+5)
            self.answer_packet[num_regs*2+3] = crc & 0xff
            self.answer_packet[num_regs*2+4] = (crc >> 8) & 0xff
            self.answer_packet_size = num_regs*2+5
        return self.answer_packet_size

    def modbus_func_4(self, packet, length):
        '''read input registers'''
        self.answer_packet_size = 0
        start_address = (packet[2] << 8) + (packet[3])
        num_regs = (packet[4] << 8) + (packet[5])
        space_num, position = self.reg_address_in_space(start_address, num_regs)
        if (num_regs < 1) or (num_regs > 125) or (space_num<0):
            logging.error("f16 illegal space for address - {} size - {}".format(start_address, num_regs))
            self.size_answer_packet = 5
            self.answer_packet[0] = packet[0]
            self.answer_packet[1] = packet[1]|0x80
            self.answer_packet[2] = 0x03
            crc = self.calc_crc(self.answer_packet, 5)
            self.answer_packet[3] = crc << 8 & 0xff
            self.answer_packet[4] = crc & 0xff
            self.answer_packet_size = 5
        else:
            self.answer_packet[0] = packet[0]
            self.answer_packet[1] = packet[1]
            self.answer_packet[2] = num_regs*2
            for i in range(num_regs):
                self.answer_packet[i*2 + 3] = (self.spaces[space_num]["buffer"][i + position] >> 8) & 0xff
                self.answer_packet[i*2 + 4] = (self.spaces[space_num]["buffer"][i + position]) & 0xff
            crc = self.calc_crc(self.answer_packet, num_regs*2+5)
            self.answer_packet[num_regs*2+3] = crc & 0xff
            self.answer_packet[num_regs*2+4] = (crc >> 8) & 0xff
            self.answer_packet_size = num_regs*2+5
        return self.answer_packet_size

    def modbus_func_6(self, packet, length):
        ''' write one word '''
        self.answer_packet_size = 0
        start_address = (packet[2] << 8) + (packet[3])
        space_num, position = self.reg_address_in_space(start_address, 1)
        if space_num < 0:
            logging.error("f6 illegal space for address - {}".format(start_address))
            self.size_answer_packet = 5
            self.answer_packet[0] = packet[0]
            self.answer_packet[1] = packet[1]|0x80
            self.answer_packet[2] = ILLEGAL_DATA_ADDRESS
            crc = self.calc_crc(self.answer_packet, 5)
            self.answer_packet[3] = crc << 8 & 0xff
            self.answer_packet[4] = crc & 0xff
            self.answer_packet_size = 5
        else:
            self.answer_packet[0] = packet[0]
            self.answer_packet[1] = packet[1]
            self.answer_packet[2] = packet[2]
            self.answer_packet[3] = packet[3]
            self.answer_packet[4] = packet[4]
            self.answer_packet[5] = packet[5]
            self.spaces[space_num]["buffer"][position] = ((packet[4] << 8) + packet[5]) & 0xffff
            crc = self.calc_crc(self.answer_packet, 8)
            self.answer_packet[6] = crc & 0xff
            self.answer_packet[7] = (crc >> 8) & 0xff
            self.answer_packet_size = 8
        return self.answer_packet_size

    def modbus_func_16(self, packet, length):
        ''' write words '''
        self.answer_packet_size = 0
        start_address = (packet[2] << 8) + (packet[3])
        num_regs = (packet[4] << 8) + (packet[5])
        space_num, position = self.reg_address_in_space(start_address, num_regs)
        if (num_regs < 1) or (num_regs > 125) or (space_num < 0):
            logging.error("f16 illegal space for address - {} size - {}".format(start_address, num_regs))
            self.size_answer_packet = 5
            self.answer_packet[0] = packet[0]
            self.answer_packet[1] = packet[1]|0x80
            self.answer_packet[2] = ILLEGAL_DATA_ADDRESS
            crc = self.calc_crc(self.answer_packet, 5)
            self.answer_packet[3] = crc << 8 & 0xff
            self.answer_packet[4] = crc & 0xff
            self.answer_packet_size = 5
        else:
            self.answer_packet[0] = packet[0]
            self.answer_packet[1] = packet[1]
            self.answer_packet[2] = packet[2]
            self.answer_packet[3] = packet[3]
            self.answer_packet[4] = packet[4]
            self.answer_packet[5] = packet[5]
            for i in range(num_regs):
                self.spaces[space_num]["buffer"][i + position] = 0
                self.spaces[space_num]["buffer"][i + position] = self.answer_packet[i*2 + 4]
                self.spaces[space_num]["buffer"][i + position] += (self.answer_packet[i * 2 + 3] >> 8)
            crc = self.calc_crc(self.answer_packet, 8)
            self.answer_packet[6] = crc & 0xff
            self.answer_packet[7] = (crc >> 8) & 0xff
            self.answer_packet_size = 8
        return self.answer_packet_size


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
    mdb_device = ModbusDevice(device_description, options.port, options.baudrate,
                                        options.parity, options.rtscts, options.xonxoff)
    print(mdb_device.spaces)
    if device_description["udp_adv"]:
        print("start udp advertisment")
        udp_port_self = 65500
        buffer_size = 1512
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Enable broadcasting mode
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", udp_port_self))
        thread.start_new_thread(udp_listening, (sock,))
    while 1:
        q = get_ch()
        if q:
          print(ord(q))
          if ord(q) == 113:   #q
              sys.exit(1)


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
