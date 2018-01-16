#!/c/Python33/ python
import sys
import time
import _thread as thread
MAX_RECEIVE_BYTE = 255
serial_is_open = 0
receive_timer = 0
receive_byte_num = 0
receive_buff = [0 for x in range(MAX_RECEIVE_BYTE)]


def com_init(port, baudrate, parity, rtscts, xonxoff):
    global serial_is_open
    try:
        import serial
    except ImportError:
        serial_is_open = 0
        print("could not import\n")
        return serial_is_open
    try:
        try:
            serial_port = serial.serial_for_url(port, baudrate, parity=parity,
                                                rtscts=rtscts, xonxoff=xonxoff, timeout=1)
        except AttributeError:
            # happens when the installed pyserial is older than 2.5. use the
            # Serial class directly then.
            serial_port = serial.Serial(port, baudrate, parity=parity,
                                        rtscts=rtscts, xonxoff=xonxoff, timeout=1)
        print(serial_port.name)  # check which port was really used
        serial_is_open = 1
        sys.stderr.write('--- modbus device on %s: %d,%s,%s,%s ---\n' % (
            serial_port.portstr,
            serial_port.baudrate,
            serial_port.bytesize,
            serial_port.parity,
            serial_port.stopbits,
        ))
    except serial.SerialException as e:
        serial_is_open = 0
        print("could not open port \n")
    if serial_is_open:
        return serial_port
    else:
        return serial_is_open


def com_start_list(serial_port, device):
    thread.start_new_thread(com_list, (serial_port, device))


def com_list(serial_port_list, device):
    global receive_timer
    global receive_byte_num
    receive_byte_num = 0
    packet_num = 0
    print("start_com_listing")
    receive_timer = time.time()
    while 1:                 
        if (time.time() > (receive_timer+0.02)) & (receive_byte_num!=0):
#            print([receive_buff[x] for x in range(receive_byte_num)])
            if device.receive_rtu_packet(receive_buff, receive_byte_num):
                send_packet(serial_port_list, device.answer_packet, device.answer_packet_size)
            else:
                print('error_packet',receive_buff[0:receive_byte_num])
            receive_byte_num = 0
            packet_num += 1
        serial_port_list.timeout = 0.03
        receive_char = serial_port_list.read(1)
        if receive_char:
            receive_timer = time.time()
            if receive_byte_num >=MAX_RECEIVE_BYTE:
                print('error max_packet_size')
                receive_byte_num =0
            receive_buff[receive_byte_num] = ord(receive_char)
            receive_byte_num += 1


def send_packet(port, buff, size):
    packet = buff[0:size]
    port.write(packet)
    print(buff[0:size])


def close(serial_port):
    global serial_is_open
    if serial_is_open:
        serial_port.close()