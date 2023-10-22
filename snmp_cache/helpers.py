'''
Helper functions

'''
import ipaddress

def mac_decimal_to_hex(mac_str: str):
    """ Take the mac address in a decimal string format from SNMP query to a hex based string """
    octets = mac_str.split('.')
    mac_address = ''
    for octet in octets:
        mac_address = mac_address + str(hex(int(octet))[2:]).zfill(2)
    return mac_address


def mac_binary_to_hex(mac_bytes: bytes):
    """ Take the mac address in byte format and convert to a hex string """
    mac_address = ''
    for mac_byte in mac_bytes:
        mac_address = mac_address + str(hex(mac_byte)[2:]).zfill(2)
    return mac_address


def ip_binary_to_str(ip_bytes: bytes):
    """ Take the IP address in byte format and convert to an IP string """
    ip_address = ''
    if isinstance(ip_bytes, ipaddress.IPv4Address):
        return str(ip_bytes)
    else:
        for ip_byte in ip_bytes:
            ip_address = ip_address +'.' + str(ip_byte)
        return ip_address[1:]


def normalize_mac(mac_address: str, delimiter=':'):
    """ Returns the MAC address normalized with the delimeter provided (can be blank) """
    mac_text = mac_address.replace(':', '').replace('-', '')
    return mac_text[0:2] + delimiter + mac_text[2:4] + delimiter + mac_text[4:6] + delimiter + mac_text[6:8] + \
        delimiter + mac_text[8:10] + delimiter + mac_text[10:12]


def bytes_to_str(array: bytes):
    """ return a string from a byte array """ 
    return array.decode()
