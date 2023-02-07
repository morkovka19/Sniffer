from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

# while True:
# a = sniff()

def ip_to_file(IP_list):
    try:
        with open("ip_log.log", 'a') as IPfile:
            for IP_elem in IP_list:
                IPfile.write(
                    "--|IP|--\n{0}->{1}\nVersion: {2}\nihl:{3}\ntos: {4}\nlength: {5}\nid: {6}\nflags: {7}\nfrag: {8}\nttl: {9}\nSum: {10}\n--OPTIONS--\n{11}\n-------------\n".format(
                        IP_elem.src,
                        IP_elem.dst,
                        IP_elem.version,
                        IP_elem.ihl,
                        IP_elem.tos,
                        IP_elem.len,
                        IP_elem.id,
                        IP_elem.flags,
                        IP_elem.frag,
                        IP_elem.ttl,
                        hex(int(IP_elem.chksum)),
                        IP_elem.options,
                    ))
    except Exception:
        print("Ошибка при работе с файлом")


def tcp_to_file(TCP_list):
    try:
        with open('TCP_log.log', 'a') as TCPfile:
            for TCP_elem in TCP_list:
                TCPfile.write(
                    "--|TCP|--\n{0}->{1}\nseq: {2}\nack:{3}\nData offset: {4}\nReserved: {5}\nFlags: {6}\nWindow: {7}\nSum: {8}\nurgptr: {9}\n--OPTIONS--\n{10}\n------------\n".format(
                        TCP_elem.sport,
                        TCP_elem.dport,
                        TCP_elem.seq,
                        TCP_elem.ack,
                        TCP_elem.dataofs,
                        TCP_elem.reserved,
                        TCP_elem.flags,
                        TCP_elem.window,
                        hex(int(TCP_elem.chksum)),
                        TCP_elem.urgptr,
                        TCP_elem.options,
                    ))
    except Exception:
        print("Ошибка при работе с файлом")


def udp_to_file(UDP_list):
    try:
        with open("UDP_log.log", 'a') as UDPfile:
            for UDP_elem in UDP_list:
                UDPfile.write("--|UDP|--\n{0}->{1}\nLength: {2}\nSum:{3}\n------------\n".format(
                    UDP_elem.sport,
                    UDP_elem.dport,
                    UDP_elem.len,
                    hex(int(UDP_elem.chksum)),
                ))
    except Exception:
        print("Ошибка при работе с файлом")


def icmp_to_file(ICMP_list):
    try:
        with open("ICMP_log.log", 'a') as ICMPfile:
            for ICMP_elem in ICMP_list:
                ICMPfile.write(
                    "--|ICMP|--\nType: {0}\nCode: {1}\nSum: {2}\nId: {3}\nseq: {4}\nunused: {5}\n------------\n".format(
                        ICMP_elem.type,
                        ICMP_elem.code,
                        hex(int(ICMP_elem.chksum)),
                        ICMP_elem.id,
                        ICMP_elem.seq,
                        ICMP_elem.unused
                    ))
    except Exception:
        print("Ошибка при работе с файлом")


def start_sniffing():
    run = True
    while run:
        try:
            a = sniff(count=10)
            a.show()
            # print(a[IP])
            ip_to_file(a[IP])
            # print(a[TCP])
            tcp_to_file(a[TCP])
            # print(a[UDP])
            udp_to_file(a[UDP])
            # print(a[ICMP])
            icmp_to_file(a[ICMP])
            print("10 packages saved")
        except Exception:
            print("Ошибка.")
            run = False


if __name__ == "__main__":
    start_sniffing()
