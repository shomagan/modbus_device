import msvcrt
import sys
try:
    from serial.tools.list_ports import comports
except ImportError:
    comports = None
DEFAULT_PORT = 1
DEFAULT_BAUDRATE = 38400
DEFAULT_RTS = None
DEFAULT_DTR = None


def main():
    import optparse
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

    group = optparse.OptionGroup(parser, "MODBUS settings")

    group.add_option("-m",
                     dest="modbus_address",
                     action="store",
                     help="modbus address ",
                     type='int',
                     default=4
                     )

    parser.add_option_group(group)

    (options, args) = parser.parse_args()

    options.parity = options.parity.upper()
    if options.parity not in 'NEOSM':
        parser.error("invalid parity")

#    if options.cr and options.lf:
 #       parser.error("only one of --cr or --lf can be specified")

#    if options.menu_char == options.exit_char:
 #       parser.error('--exit-char can not be the same as --menu-char')
    import com_transfer
    serial_port = com_transfer.com_init(options.port, options.baudrate, options.parity, options.rtscts, options.xonxoff)
    print(serial_port)
    import modbus_parser
    mdb_device = modbus_parser.ModbusHandler(options.modbus_address)
    if com_transfer.serial_is_open:

        com_transfer.com_start_list(serial_port, mdb_device)
    packet_num = 0
    while 1:
        q = msvcrt.getch()
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
