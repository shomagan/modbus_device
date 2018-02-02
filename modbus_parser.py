import time 
import struct
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
            print (num_byte)
            crc_in_packet = buff[num_byte - 2] + (buff[num_byte - 1] << 8)
            if self.check_crc(buff, num_byte) == crc_in_packet:
                if buff[0] == self.modbus_address:
                    self.packet_receive_num += 1
                    print('->--->self<---<-',buff[0:num_byte])
                    print(time.asctime(),'good packet number',self.packet_receive_num)
                    if buff[1] == 3 or buff[1] == 4:
                        size = self.make_answer_3(buff, num_byte)
                        return size
                    else:
                        return 0
                elif buff[0] == 5:
                    self.packet_receive_num += 1
                    print('->--->5<---<-',buff[0:num_byte])
                    print(time.asctime(),'good packet number',self.packet_receive_num)
                    if buff[1] == 3 or buff[1] == 4:
                        size = self.make_answer_3(buff, num_byte)
                        return size
                    else:
                        return 0
                elif buff[0] == 6:
                    self.packet_receive_num += 1
                    print('->--->6<---<-',buff[0:num_byte])
                    print(time.asctime(),'good packet number',self.packet_receive_num)
                    if buff[1] == 3 or buff[1] == 4:
                        size = self.make_answer_3(buff, num_byte)
                        return size
                    else:
                        return 0

                elif buff[0] == 0:
                    self.packet_receive_num += 1
                    print('->--->0<---<-',buff[0:num_byte])

                    print(time.asctime(),'good packet number',self.packet_receive_num)
                    if buff[1] == 3 or buff[1] == 4:
                        size = self.make_answer_3(buff, num_byte)
                        return size
                    else:
                        return 0


                else:
                    print('receive packet not for mi')
                    print('->--->.<---<-',buff[0:num_byte])
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
                if buff[1] == 3 | buff[1] == 4 :
                    size = self.make_answer_3(buff[6:], num_byte)
                    self.answer_packet_size+=4
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
            self.answer_packet[3] = crc << 8 & 0xff
            self.answer_packet[4] = crc & 0xff
            self.answer_packet_size = 5
        else:
            temp_buff_f = [float(i) for i in range(255)]
            temp_buff_b = [i for i in range(255*4)]
            for i in range(255):
                value = struct.unpack('<I', struct.pack('<f', temp_buff_f[i] + float(self.packet_receive_num)))

                temp_buff_b[i*4] = ((value[0])>>8)&0xff
                temp_buff_b[i*4+1] = (value[0])&0xff
                temp_buff_b[i*4+2] = ((value[0])>>24)&0xff
                temp_buff_b[i*4+3] = ((value[0])>>16)&0xff

#            value = packet[14]|(packet[15]<<8)|(packet[16]<<16)|(packet[17]<<24)
 #           flo32 = struct.pack('I',value)
  #          Volume_FlowRate_Gas = struct.unpack('f',flo32)

            self.answer_packet[0] = packet[0]
            self.answer_packet[1] = packet[1]
            self.answer_packet[2] = num_regs*2
            for i in range(num_regs*2):
                self.answer_packet[i+3] = temp_buff_b[i+(start_address&0xfc)]
            crc = self.check_crc(self.answer_packet, num_regs*2+5)
            self.answer_packet[num_regs*2+3] = crc & 0xff
            self.answer_packet[num_regs*2+4] = (crc >> 8) & 0xff
            self.answer_packet_size = num_regs*2+5
        return self.answer_packet_size



