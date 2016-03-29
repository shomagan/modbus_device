class ModbusHandler(object):
    def __init__(self, address):
        print("add modbus device with address", address)
        self.modbus_address = address
        self.packet_receive_num = 0
        self.answer_packet = [0 for x in range(0, 1024)]
        self.answer_packet_size = 0
        self.size_answer_packet = 0

    def __del__(self):
        print("dlt handler")

    def receive_rtu_packet(self, buff, num_byte):
        if num_byte > 4:
            crc_in_packet = buff[num_byte - 2] + (buff[num_byte - 1] << 8)
            print(buff[0:num_byte])
            if self.check_crc(buff, num_byte) == crc_in_packet:
                if buff[0] == self.modbus_address:
                    self.packet_receive_num += 1
                    if buff[1] == 3:
                        size = self.make_answer_3(buff, num_byte)
                        return size
                    else:
                        return 0
                else:
                    return 0
            else:
                return 0
        else:
            return 0

    def receive_tcp_packet(self, buff, num_byte):
        if num_byte > 10:
            print(buff[0:num_byte])
            if buff[6] == self.modbus_address:
                self.packet_receive_num += 1
                if buff[1] == 3:
                    size = self.make_answer_3(buff[6:], num_byte)
                    for i in range(0, 6):
                        self.answer_packet.insert(i,buff[i])
                    return size
                else:
                    return 0
            else:
                return 0
        else:
            return 0

    @staticmethod
    def check_crc(pck, packet_length):
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

    def make_answer_3(self, packet, length):
        self.answer_packet_size = 0
        start_address = (packet[2] << 8) + (packet[3])
        num_regs = (packet[4] << 8) + (packet[5])
        if (num_regs < 1) | (num_regs > 125):
            self.size_answer_packet = 5
            self.answer_packet[0] = packet[0]
            self.answer_packet[1] |= 0x80
            self.answer_packet[2] = 0x03
            crc = self.check_crc(self.answer_packet, 5)
            self.answer_packet[3] = crc << 8
            self.answer_packet[4] = crc
            self.answer_packet_size = 5
        else:
            self.answer_packet[0] = packet[0]
            self.answer_packet[1] = packet[1]
            self.answer_packet[2] = num_regs*2
            for i in range(num_regs*2):
                self.answer_packet[i+3] = (i + self.packet_receive_num)&0xff
            crc = self.check_crc(self.answer_packet, num_regs*2+5)
            self.answer_packet[num_regs*2+3] = crc & 0xff
            self.answer_packet[num_regs*2+4] = (crc >> 8) & 0xff
            self.answer_packet_size = num_regs*2+5
        return self.answer_packet_size



