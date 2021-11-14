import time 
import struct
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

class ModbusHandler(object):
    def __init__(self, device_description):
        print("add modbus device with address", device_description["address"])
        self.modbus_address = device_description["address"]
        self.packet_receive_num = 0
        self.answer_packet = [0 for x in range(0, 1024)]
        self.answer_packet_size = 0
        self.size_answer_packet = 0
        self.spaces = []
        for i in range(device_description["spaces_num"]):
            space = {}
            buffer = [i for i in range(device_description["spaces"][i]["registers_num"]*2)]
            space["buffer"] = buffer
            space.update(device_description["spaces"][i])
            self.spaces.append(space)

    def __del__(self):
        print("dlt handler")

    def receive_rtu_packet(self, buff, num_byte, crc_check=1):
        if num_byte > 4:
            print (num_byte)
            crc_in_packet = buff[num_byte - 2] + (buff[num_byte - 1] << 8)
            if crc_check == 0 or self.calc_crc(buff, num_byte) == crc_in_packet:
                if buff[0] == self.modbus_address:
                    self.packet_receive_num += 1
                    print(time.asctime(),'good packet number',self.packet_receive_num)
                    size = 0
                    if buff[1] == 3:
                        size = self.modbus_func_3(buff, num_byte)
                        return size
                    if buff[1] == 4:
                        size = self.modbus_func_4(buff, num_byte)
                        return size
                    elif buff[1] == 6:
                        size = self.handle_read_6(buff, num_byte)
                        return size
                    elif buff[1] == 16:
                        size = self.handle_read_16(buff, num_byte)
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
            if (reg_address >= i["start_address"]) and ((reg_address + regs_num) < (i["start_address"]+i["registers_num"])):
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
        if (num_regs < 1) or (num_regs > 125) or (space_num<0):
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
                self.answer_packet[i*2 + 4] = (self.spaces[space_num]["buffer"][i + position] >> 8)
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
                self.answer_packet[i*2 + 4] = (self.spaces[space_num]["buffer"][i + position] >> 8)
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

