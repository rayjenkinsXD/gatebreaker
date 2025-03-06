import psutil
from abc import ABC, abstractmethod
import socket
import enum
import random
import time
import os


class SameOSILevelExpection(Exception):
    pass


class NetworkPacket(ABC):
    """
    NetworkPacket  наследуют  все  типы  пакетов  всех уровней OSI. Этот абстрактный
    класс  стремится  реализовать  основополагающий  механизм  модели - инкапсуляция
    и деинкапсуляция при помощи абстрактных методов pack() и unpack() соответственно
    """
    @staticmethod
    def getMACByInterface(interface: str) -> str | None:
        """
        Метод  возвращает MAC  адрес в формате строки. Особенности представления
        MAC  адреса  на  других  операционных системах (в  Windows  это  "-") не 
        учитываются, т. к. socket.AF_PACKET реализовал только в UNIX.
        """
        for interface_name, interface_data in psutil.net_if_addrs().items():
            if interface_name == interface and interface_data:
                for interface_address in interface_data:
                    if interface_address.family == socket.AF_PACKET:
                        return interface_address.address
                    
    @staticmethod
    def getIPByInterface(interface: str) -> str | None:
        """
        Метод возвращает IP адрес в формате строки по MAC адресу
        """
        for interface_name, interface_data in psutil.net_if_addrs().items():
            if interface_name == interface and interface_data:
                for interface_address in interface_data:
                    if interface_address.family == socket.AF_INET:
                        return interface_address.address

    @staticmethod
    def convertMACToBytes(mac: str) -> bytearray:
        mac = mac.replace(":", "")
        return bytearray.fromhex(mac)

    @staticmethod
    def convertIPToBytes(ip: str) -> bytearray:
        return bytearray(socket.inet_aton(ip))
    
    @staticmethod
    def convertBytesToMAC(raw_data: bytes | bytearray) -> str:
        mac = raw_data.hex()
        return f"{mac[0:2]}:{mac[2:4]}:{mac[4:6]}:{mac[6:8]}:{mac[8:10]}:{mac[10:12]}"
    
    @staticmethod
    def convertBytesToIP(raw_data: str) -> str:
        return socket.inet_ntoa(raw_data)
    
    @staticmethod
    def checksum(data):
        """
        Я пока не настолько крутой, чтобы при помощи битовых операций писать
        алгоритм вычисления чексуммы, да и для текущей задачи это не надо,
        поэтому повзаимствовал код.
        
        !!!! Это единственный не мой код. Все остальное писалось с нуля самостоятельно !!!!
        """
        if len(data) % 2 != 0:
            data += b'\x00'  # Дополняем до четного числа байт

        checksum = 0

        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        return (~checksum & 0xFFFF).to_bytes(2, "big")

    @abstractmethod
    def pack(self) -> bytearray:
        """
        Упаковывает данные сетевого пакета любого уровня OSI и конвертирует в набор
        байт, который в последствии можно отправить через сырой сокет.
        """
        pass

    @staticmethod
    @abstractmethod
    def unpack(raw_data: bytes) -> bytearray:
        """
        Обратное  действие  методу  pack()  -  на  вход подаются байты и, начиная с 
        нижележащих протоколов, они деинкапсулируются наверх.
        """
        pass


class ICMPPacket(ABC):
    """ Представляет ICMP пакет и реализует общие методы """


class ICMPEchoRequest(ICMPPacket, NetworkPacket):
    """
    В условиях задачи ICMP пакеты не поддерживают:
    - Отправку в очереди (проверка Identifier, Sequence number)
    - Связывание запроса и ответа (сравнение Identifier)
    """
    def __init__(self):
        self._type = bytearray([0x08])
        self._code = bytearray([0x00])
        self._checksum = bytearray([0x00, 0x00])           # Вычисляется во время упаковки

        # Из-за описанных в комментариях объявления класса ограничений не
        # реализуется  проверка порядка следования и связывание запросов,
        # поэтому  идентификаторы  генерируются  единожды  и все короч :ь
        self._identifier = (os.getpid() & 0xFFFF).to_bytes(2, "big")

        sequence_number = 1
        self._sequence_number = sequence_number.to_bytes(2, "big")

        # ToD формат ICMP пакета: 
        # https://shorturl.at/GaLh5
        # https://habr.com/ru/companies/pt/articles/136677/
        # http://www.tcpipguide.com/free/t_ICMPv4TimestampRequestandTimestampReplyMessages-2.htm
        # https://currentmillis.com/
        current_time = time.time()
        seconds = int(current_time)
        milisecunds = int((current_time - seconds) * 1_000_000)

        seconds = bytearray(seconds.to_bytes(8, "little"))
        milisecunds = bytearray(milisecunds.to_bytes(8, "little"))

        self._timestamp = bytearray()
        self._timestamp.extend(seconds)
        self._timestamp.extend(milisecunds)

        # Не знаю, что за данные передаются всеми ICMP пакетами, но они одинаковые и,
        # полагаю, служебные.
        self._data = bytes(range(0x10, 0x38))

    def pack(self) -> bytearray:    
        result = bytearray()
        result.extend(self._type)
        result.extend(self._code)
        result.extend(self._checksum)  # чексумма вычислится позже
        result.extend(self._identifier)
        result.extend(self._sequence_number)
        result.extend(self._timestamp)
        result.extend(self._data)

        result[2:4] = NetworkPacket.checksum(result)

        return result


    @staticmethod
    def unpack(raw_data: bytes) -> object:
        """ В приеме ICMP Echo Request пакетов пока нет необходимости """
        pass


class IPPacketFlagsEnum(enum.Enum):
    """ Временно поддерживается два типа флагов """
    DONT_FRAGMENT = bytearray([0x40, 0x00])
    WITHOUT_FLAGS = bytearray([0x00, 0x00])


class IPv4Packet(NetworkPacket):
    """
    Класс  начинен НАМЕРЕННО оставленными костылями, чтобы не реализовывать вещи,
    не касающиеся текущей задачи (написать софт, инициирующий ARP спуффинг атаку)
    Например,  никак  не  реализована фрагментация, потому что нужные ICMP пакеты
    ее запрещают.
    """
    def __init__(self, incapsulation: NetworkPacket, source_ip: str, destination_ip: str):
        # TODO: Protocol Version и Header length задаются одним байтом, что не универсально.
        # Нужно это изменить при помощи битовых операций в дальнейшем.
        self._version_and_IHL = bytearray([0x45])  # Protocol version
        self._DCSP = bytearray([0x00])             # дефолтный приоритет для сетевых пакетов
        self._total_length = None                  # подсчитывается динамически во время упаковки

        # случайное число. фрагментация пока не реализована
        random_frag_id = random.randint(0, 65355)
        self._identificator = random_frag_id.to_bytes(2, "big")

        # фрагментация по-умолчанию отключена
        self._flags = IPPacketFlagsEnum.DONT_FRAGMENT.value

        self._ttl = bytearray([0x40])              # по-умолчанию TTL равен ICMP Request TTL
        self._incapsulation = incapsulation

        if isinstance(self._incapsulation, ICMPPacket):
            self._protocol = bytearray([0x01])
        else:
            # TODO: Сделать обработку ошибки в случае отсутствия обработчика инкапсуляции
            pass

        self._checksum = None  # Генерируется при упаковке
        self._source = NetworkPacket.convertIPToBytes(source_ip)
        self._destination = NetworkPacket.convertIPToBytes(destination_ip)

    def pack(self) -> bytearray:
        result = bytearray()
        result.extend(self._version_and_IHL)
        result.extend(self._DCSP)
        result.extend(bytearray([0x00, 0x00]))  # length высчитывается позже
        result.extend(self._identificator)
        result.extend(self._flags)
        result.extend(self._ttl)
        result.extend(self._protocol)
        result.extend(bytearray([0x00, 0x00]))  # Checksum высчитывается в конце
        result.extend(self._source)
        result.extend(self._destination)
        result.extend(self._incapsulation.pack())

        result[2:4] = len(result).to_bytes(2, "big")
        
        result[10:12] = NetworkPacket.checksum(result[:20])

        return result

    def unpack():
        pass

    @property
    def flags(self) -> object:
        for flag in IPPacketFlagsEnum:
            if flag.value == self._flags:
                return flag
            
    @flags.setter
    def flags(self, flag: object) -> None:
        # TODO: Добавить проверку
        self._flags = flag.value

    @property
    def ttl(self) -> int:
        return int.from_bytes(self._ttl)
    
    @ttl.setter
    def ttl(self, value: int) -> None:
        # TODO: Добавить проверку
        self._ttl = bytearray(value.to_bytes(1, "big"))


class ARPPacket(NetworkPacket):
    """
    Базовый  класс протокола ARP. Задает общую структуру пакета и реализует метод
    pack(). Дочерние классы: ARPRequest, ARPReply меняют лишь _opcode
    """
    def __init__(self, sender_mac: str, sender_ip: str, target_mac: str | None, target_ip: str):
        self._hardware_type = bytearray([0x00, 0x01])
        self._protocol_type = bytearray([0x08, 0x00])
        self._hardware_size = bytearray([0x06])
        self._protocol_size = bytearray([0x04])
        self._opcode = None  # Это свойство устанавливается дочерними классами.
        self._sender_mac = self.convertMACToBytes(sender_mac)
        self._sender_ip = self.convertIPToBytes(sender_ip)

        if target_mac is None:
            self._target_mac = self.convertMACToBytes("00:00:00:00:00:00")
        else:
            self._target_mac = self.convertMACToBytes(target_mac)

        self._target_ip = self.convertIPToBytes(target_ip)

    def pack(self):
        result = bytearray()
        result.extend(self._hardware_type)
        result.extend(self._protocol_type)
        result.extend(self._hardware_size)
        result.extend(self._protocol_size)
        result.extend(self._opcode)
        result.extend(self._sender_mac)
        result.extend(self._sender_ip)
        result.extend(self._target_mac)
        result.extend(self._target_ip)

        return result
    
    @staticmethod
    def unpack(raw_data: bytearray) -> object:
        opcode = bytearray(raw_data[6:8])
        sender_mac = NetworkPacket.convertBytesToMAC(raw_data[8:14])
        sender_ip = NetworkPacket.convertBytesToIP(raw_data[14:18])
        target_mac = NetworkPacket.convertBytesToMAC(raw_data[18:24])
        target_ip = NetworkPacket.convertBytesToIP(raw_data[24:28])

        if opcode == bytearray([0x00, 0x01]):
            return ARPRequest(sender_mac, sender_ip, target_mac, target_ip)
        elif opcode == bytearray([0x00, 0x02]):
            return ARPReply(sender_mac, sender_ip, target_mac, target_ip)
        
    @property
    def sender_mac(self):
        return NetworkPacket.convertBytesToMAC(self._sender_mac)
    
    @property
    def sender_ip(self):
        return NetworkPacket.convertBytesToIP(self._sender_ip)
    
    @property
    def target_mac(self):
        return NetworkPacket.convertBytesToMAC(self._target_mac)
    
    @property
    def target_ip(self):
        return NetworkPacket.convertBytesToIP(self._target_ip)


class ARPRequest(ARPPacket):
    def __init__(self, sender_mac: str, sender_ip: str, target_mac: str | None, target_ip: str):
        super().__init__(sender_mac, sender_ip, target_mac, target_ip)
        self._opcode = bytearray([0x00, 0x01])

    def request(interface: str, target: str) -> object | None:
        """
        Отправляет корректный ARP запрос для того, чтобы получить MAC адрес цели

        TODO: Сделать возможность делать направленные запросы (как шлюз -> хост)
        """
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0x0806))
        
        sender_mac = NetworkPacket.getMACByInterface(interface)
        sender_ip = NetworkPacket.getIPByInterface(interface)
        arp_packet = ARPRequest(sender_mac, sender_ip, None, target)
        ethernet_frame = EthernetFrame(arp_packet, sender_mac, EthernetFrame.BROADCAST_MAC)

        sock.send(ethernet_frame.pack())
        sock.settimeout(0.45)

        try:
            response = sock.recv(100)
            sock.close()
            ethernet_frame = EthernetFrame.unpack(response)

            return ethernet_frame.ethertype
        except TimeoutError:
            sock.close()
            
            return None


class ARPReply(ARPPacket):
    def __init__(self, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str):
        super().__init__(sender_mac, sender_ip, target_mac, target_ip)
        self._opcode = bytearray([0x00, 0x02])


class EthernetFrame(NetworkPacket):
    BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

    def __init__(self, incapsulation: NetworkPacket, source: str, destination: str):
        self._source = self.convertMACToBytes(source)
        self._destination = self.convertMACToBytes(destination)
        self._ethertype = None
        self._incapsulation = incapsulation

        # TODO: Нужно использовать EthertypesEnum
        if isinstance(incapsulation, ARPPacket):
            self._ethertype = bytearray([0x08, 0x06])  # https://en.wikipedia.org/wiki/EtherType
        elif isinstance(incapsulation, IPv4Packet):
            self._ethertype = bytearray([0x08, 0x00])
        else:
            raise SameOSILevelExpection("Ethernet frame can't pack ethernet frame.")

    def pack(self):
        result = bytearray()
        result.extend(self._destination)
        result.extend(self._source)
        result.extend(self._ethertype)
        result.extend(self._incapsulation.pack())

        return result
    
    @staticmethod
    def unpack(raw_data: bytes) -> object:
        raw_data = bytearray(raw_data)
        destination = NetworkPacket.convertBytesToMAC(raw_data[0:6])
        source = NetworkPacket.convertBytesToMAC(raw_data[6:13])
        type = bytearray(raw_data[12:14])
        payload = raw_data[14::]

        # TODO: Нужно написать EthertypesEnum
        if type == bytearray([0x08, 0x06]):
            deincapsulation = ARPPacket.unpack(payload)
            
        return EthernetFrame(deincapsulation, source, destination)
    
    @property
    def source(self):
        return NetworkPacket.convertBytesToMAC(self._source)
    
    @property
    def destination(self):
        return NetworkPacket.convertBytesToMAC(self._destination)
    
    @property
    def ethertype(self):
        return self._incapsulation
