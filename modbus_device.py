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
import optparse
import com_transfer
import tcp_ip_transfer
import modbus_parser
DEFAULT_PORT = "COM2"
DEFAULT_BAUDRATE = 115200
DEFAULT_RTS = None
DEFAULT_DTR = None


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


def main():

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

    group_modbus = optparse.OptionGroup(parser, "MODBUS settings")

    group_modbus.add_option("-m",
                            dest="modbus_address",
                            action="store",
                            help="modbus address ",
                            type='int',
                            default=3
                            )

    parser.add_option_group(group_modbus)
    group_ip = optparse.OptionGroup(parser, "IP settings")

    group_ip.add_option("--iport",
                        dest="ip_port",
                        action="store",
                        help="ip port",
                        type='int',
                        default=502
                        )

    parser.add_option_group(group_ip)

    (options, args) = parser.parse_args()

    options.parity = options.parity.upper()
    if options.parity not in 'NEOSM':
        parser.error("invalid parity")

#    if options.cr and options.lf:
 #       parser.error("only one of --cr or --lf can be specified")

#    if options.menu_char == options.exit_char:
 #       parser.error('--exit-char can not be the same as --menu-char')
    print(options)
    print(PLATFORM)
    serial_port = com_transfer.com_init(options.port, options.baudrate,
                                        options.parity, options.rtscts, options.xonxoff)

    ip_socket = tcp_ip_transfer.tcp_ip_init(options.ip_port)

    mdb_device = modbus_parser.ModbusHandler(options.modbus_address)
    if com_transfer.serial_is_open:
        com_transfer.com_start_list(serial_port, mdb_device)
    if ip_socket:
        tcp_ip_transfer.tcp_ip_start_list(ip_socket, mdb_device)
    packet_num = 0
    while 1:
        q = get_ch()
        print(ord(q))
        if ord(q) == 113:   #q
            com_transfer.close(serial_port)
            sys.exit(1)
        if mdb_device.packet_receive_num != packet_num:
            print(mdb_device.packet_receive_num)







if __name__ == '__main__':
    '''request modbus packet on com port or tcp connect
      options:
        -m modbus address
        -p port
        -b baud rate
    '''
    main()
