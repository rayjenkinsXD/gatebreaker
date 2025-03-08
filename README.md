# Gatebreaker | Руководство

### Разработка Alpha 2.0.0
На текущий момент проект заморожен. Версия Alpha 1.0.0 на Python является прототипом, необходимым для проверки ряда гипотез. На 9 марта, 2025 успешно подтверждены, и я принялся за разработку Alpha 2.0.0, где код библиотеки будет переписан на C++

### Предисловие
Изначально это была тривиальная университетская задача, которую выудил у пятикурсника, будучи первокурсником, которую было необходимо уложить в срок в 2 месяца. Я утвердил, что сделаю за 3 недели при нулевых знаниях И сделал. И проект этот превратился в нечто большее, чем искусственная производственная задача. Этот софт - моя первая веха в компьютерной безопасности и горячо любимой сетевой инженерией в частности.

Мой подход - не списать с Habr или ChatGPT/DeepSeek и забыть, а построить фундамент из глубочайших знаний, предоставляющий возможности реализации нестандартного подхода и последующего быстрого изучения других атак и технологий, поэтому за эти 3 злополучные недели, ежедневной 5-часовой работы и сбитого режима я провел множество экспериментов в подсетях в гостях у друзей, дома и в виртуальной лаборатории и пришел к написанию собственной библиотеки, реализующей нижележащий сетевой стек, позволяющий быстро перебирать разные способы атак, не переписывая куски из 400 строк спагетти-кода.

Этот README - не только документация, но и история первого большого достижения в 2025 году. [В моем Telegram канале](https://t.me/webpodolsk/105) можно увидеть полную историю появления задачи и трудностей ее выполнения.

### Краткое описание & возможности
**gatebreaker** - это *(в будущем)* набор утилит, инициирующих атаки на канальном и сетевом уровне OSI в подсети, нацеленные на маршрутизатор. В настоящий момент основной утилитой **gatebreaker.py** реализуется ограниченный спектр атак в версии `Alpha 1.0.0`:

1. **MITM атака ARP-spoofing** между устройствами на дистрибутиве Linux *(за исключением Android)*. В случае, если устройство отличается от Linux, например, Windows, iOS, Android - происходит отказ в обслуживании. Технические подробности и dev блог будет в конце.
2. (**WIP**) **ARP-storm** - изменение ARP таблиц всех устройств подсети таким образом, чтобы устроить полный отказ в обслуживании при помощи одной единственной команды. В планах сделать так, чтобы обойти черные списки firewall'а.

### Спектр атаки
На текущий момент утилита протестированна на следующих операционных системах:
- Linux Debian 12
- OpenWRT (Router)
- HyperOS
- iPhone (AP)

### Gatebreaker Quick Start
Пока что единственная и основная утилита - `gatebreaker.py`. Используется следующим образом:

```
sudo -E python3 gatebreaker.py -i [interface] [Alice IP] [Bob IP]
```
- `-i [interface]` - сетевой интерфейс, через который происходит общение с сетью. Можно узнать при помощи команд `ip link` или `/sbin/route`
- `[Alice IP]` - IP адрес первой цели.
- `[Bob IP]` - IP адрес второй цели.

После этого в случае ошибки выведется отладочное сообщение, а в случае удачи - программа начнет работать, пока не будет нажата комбинация клавиш `Ctrl-C` - после этого выведется информация об отправленных пакетах и корректно закроется сокет.

# netlib | Документация
### Предисловие
Во время выполнения столкнулся со следующей проблемой: использовать сторонние библиотеки запрещено, и в случае монолитного кода утилиты мне бы пришлось по несколько раз переписывать большие участки кода, если потребуется провести атаку иначе. Поэтому для реализации разных атак и первоочередного углубленного обучения решил разработать собственную библиотеку, собирая все вплоть до Ethernet фреймов с нуля по RFC документам. 

Я сталкивался с незначительными, но трудно отлавливаемыми ошибками, но теперь на самом глубоком уровне знаю, как устроены протоколы Ethernet, IP, ICMP и ARP и их реализации, поведение на разных операционных системах.

### Quick Start
Отправка ICMP пакета выглядит следующим образом:

> **ВАЖНО:** В библиотеке есть баг, не позволяющий работать с Loopback интерфейсом, поэтому использовать его не рекомендуется.

```python
import netlib
import socket


# наш интерфейс из ip link или /sbin/route
INTERFACE = "wlan0"

# по интерфейсу получаем наш IP адрес
ip_sender = netlib.NetworkPacket.getIPByInterface(INTERFACE)

# и MAC адрес
mac_sender = netlib.NetworkPacket.getMACByInterface(INTERFACE)

# IP адрес получателя
ip_receiver = "172.20.10.1"

# MAC  адрес получателя можно ввести вручную, а можно послать ARP
# запрос и получить ответ (ARPRequest.request() возвращает объект
# типа  ARPReply,  который  имеет свойства sender_mac, sender_ip,
# target_mac, target_ip
mac_receiver = netlib.ARPRequest.request(INTERFACE, ip_receiver).sender_mac

# генерируем ICMP пакет
icmp_packet = netlib.ICMPEchoRequest()

# запаковываем ICMP пакет в IP пакет и добавляем данные об адресах
ip_packet = netlib.IPv4Packet(icmp_packet, ip_sender, ip_receiver)

# запаковываем IP пакет Ethernet фрейм и добавляем данные о MAC адресах
ethernet_frame = netlib.EthernetFrame(ip_packet, mac_sender, mac_receiver)

# Создаем сырой (SOCK_RAW) AF_PACKET сокет канального уровня
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sock.bind((INTERFACE, 0x0003))

sock.send(ethernet_frame.pack())

sock.close()
```

### Техническая документация
Идея `netlib.py` - реализовать модель OSI и ее основные принципы: инкапсуляция & деинкапсуляция протоколов. Как это достигается? В технической документации будет описана лишь архитектура библиотеки. За деталями реализации конкретных классов следует обратиться к коду `netlib.py` - комментариев там с избытком.

#### Основной абстрактный класс NetworkPacket
Все классы, описывающие сетевые пакеты, наследуют абстрактный класс NetworkPacket, обязывающий для обеспечения полиморфизма классы сетевых протоколов любого уровня перегрузить методы `pack()` и `unpack()`.

#### Метод pack()
`pack() -> bytearray` - метод *"запаковывает"* все свойства объекта, представляющего какой-нибудь PDU, в набор байт в big-endian порядке байт, чтобы его можно было отправить по сети.

Благодаря обеспеченному классом NetworkPacket полиморфизму, в объект EthernetFrame можно просто передать объект типа ARPPacket и при вызове метода pack() у EthernetFrame, он запакует в байты не только свои поля, но и вызовет метод `pack()` у ARPPacket. Вот листинг метода pack() класса EthernetFrame:

```python
def pack(self):
        result = bytearray()
        result.extend(self._destination)
        result.extend(self._source)
        result.extend(self._ethertype)
        result.extend(self._incapsulation.pack())

        return result
```

#### Метод unpack()
`unpack(raw_data: bytearray) -> object` - это статический метод, обратный методу `pack()`. Он парсит входящий массив байт и возвращает объект EthernetFrame, в котором к запакованному в него пакету можно обратиться по свойству incapsulation и так далее рекурсивно.
