
#!/usr/bin/python3

"""
@author: Beata Jacobsson, Linnea Korneliussen, Clara Hansson & Celina Linnerblom
Project within the course Secure Network Management at Hochchule Munchen 2024

"""

# ======================================================================================================================
# This is a template for the project in CNF / CNSM Part I
#
# Please note:
# You can use this template for your project.
# This template is a help for you.
# Implement your own idea.
#
# Python coding style:
# Use python black for formatting by running following command:
# $ black file.py
# This black command will format your python code
#
# Apart from this, please write your code very clearly and readable.
# That means:
# 1. Document at least each method/function with a block of comments: """ Block comment """
# 2. Write the authors name and the group number at the top of the document
# 3. Use keywords according to: @url https://datatracker.ietf.org/doc/html/rfc1350/
# 4. Use functions instead of very long codeblocks
# 5. Use 'speaking' variable names
# 6. Make use of global variables
# 7. Utilize meaningful print statements
#
# ======================================================================================================================

import socket
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.tftp import TFTP, TFTP_ACK, TFTP_DATA, TFTP_RRQ, TFTP_WRQ
from scapy.sendrecv import send, sr
from enum import Enum

SERVER_IP = "192.168.30.90"
CLIENT_IP = "192.168.40.50"
PROXY_IP_CLIENTSIDE = "192.168.40.80"
PROXY_IP_SERVERSIDE = "192.168.30.80"
TFTP_PORT = 69
BUFFERSIZE = 1024


class OPCode(Enum):
    """An Enumeration representing all possible OP-codes

    Args:
        Enum (bytes): The message type
    """

    RRQ = 1
    WRQ = 2
    DATA = 3
    ACK = 4
    ERROR = 5


class Proxy:
    """A class representing all possible operations, that can be executed on the proxy.

    Returns:
        object: returns an object of the class Proxy
    """

    def __init__(self) -> None:
        """This is the constructor for the Proxy Class"""
        print("The proxy is ready")

    def __get_sender_from_ip(self, ip) -> str:
        """Identifies the Sender

        Args:
            ip (str): The IP-address

        Returns:
            str: either Client or Server
        """
        if ip[8:] == "40.50":  # if the IP ends with 40.50
            return "Client"  # then this is the client
        elif ip[8:] == "30.90":  # if the IP ends with 30.90
            return "Server"  # then it's the server

    def get_opcode(self, packet) -> bytes:
        """A method for extracting the opcode from the data received by the socket.

        Args:
            packet (Byteobject): the raw packet data received by a socket

        Returns:
            bytes: The op-code can be: 1,2,3,4,5
        """
        return packet[1]

    def get_blocknumber(self, packet) -> int:
        """Identifies the blocknumber

        Args:
            packet (byteobject): the raw packet data received by a socket

        Returns:
            int: the blocknumber
        """
        block = int.from_bytes(
            packet[2:4], "big"
        )  # converts the blocknumber from bytes into int (bytes on index 2 and 3)
        return block

    def __get_data_packet_length(self, packet) -> int:
        """calculates the length of a data packet

        Args:
            packet (byteobject): the raw packet data received by a socket

        Returns:
            int: the length of the packet
        """
        return len(packet) - 4  # data packet header is 4 bytes long

    def __get_filename(self, packet) -> str:
        """Extract the filename as a string

        Args:
            packet (byteobject): the raw packet data received by a socket

        Returns:
            str: filename, like 'test511.txt'
        """
        startIndex = 2
        endIndex = packet.find(b"\00", startIndex)
        return packet[startIndex:endIndex].decode("ascii")

    def __get_error_message(self, packet) -> str:
        """Extract the error message from an ERROR packet

        Args:
            packet (byteobject): the raw packet data received by a socket

        Returns:
            str: error message
        """
        return packet[4 : len(packet) - 1].decode("ascii")

    def __get_mode(self, packet) -> str:
        """Extract the mode as a string

        Args:
            packet (byteobject): the raw packet data received by a socket

        Returns:
            str: mode, like 'netascii'
        """
        startIndex = packet.find(b"\00", 2) + 1
        endIndex = packet.find(b"\00", startIndex)
        return packet[startIndex:endIndex].decode("ascii")

    def __format_packet(self, packet) -> str:
        """Formats the contents of a packet for later printing to the console.

        Args:
            packet (Byteobject): the raw packet data received by a socket

        Returns:
            str: the formatted presentation of the packet as a string
        """
        opcode = self.get_opcode(packet)

        if opcode == OPCode.DATA.value:
            return "DATA packet| Block number: {block} | Length: {length} Bytes | Payload ".format(
                block=self.get_blocknumber(packet),
                length=self.__get_data_packet_length(packet),
            )
        elif opcode == OPCode.ACK.value:
            return "ACK packet | Block number: {block}".format(
                block=self.get_blocknumber(packet),
            )
        elif (opcode == OPCode.RRQ.value) or (opcode == OPCode.WRQ.value):
            filename, mode = packet[2 : len(packet) - 1].split(b"\x00")
            return "{op} packet | {filename} | 0 | {mode} | 0".format(
                op=OPCode(opcode).name,
                filename=self.__get_filename(packet),
                mode=self.__get_mode(packet),
            )
        else:  # only option left is an error packet
            return "ERROR packet | {err_code} | {err_msg} | 0".format(
                err_code=packet[3],
                err_msg=self.__get_error_message(packet),
            )

    def receive(self, socket: socket) -> tuple:
        """Receives incomming messages on the specified
        ip = address[0]
        port = address[1]

        Args:
            socket (socket): the socket, which receives the data

        Returns:
            tuple: returns a tuple of packet and sender address
        """
        packet, address = socket.recvfrom(1024)  # address is a tuple of (ip, port)
        print(
            "Recieved {format_packet} from {ip}:{port} ({host})\n".format(
                format_packet=self.__format_packet(packet),
                ip=address[0],
                port=address[1],
                host=self.__get_sender_from_ip(address[0]),
            )
        )
        return (packet, address)

    def forward(self, socket: socket, address, packet) -> None:
        """forwards a message from the specified socket to the specified address

        Args:
            socket (socket): the socket on which the packet is sent
            address (tuple): the address to which the packet is sent to
            packet (byteobject): the packet containing the data
        """
        print(
            "Forward {format_packet} to: {ip}:{port} ({host})\n".format(
                format_packet=self.__format_packet(packet),
                ip=address[0],
                port=address[1],
                host=self.__get_sender_from_ip(address[0]),
            )
        )
        socket.sendto(packet, address)
        
    
# proxy class ends here 


# methods starts here  

def example_for_sending_tftp_via_scapy() -> None:
    """This is an example for a crafted TFTP RRQ packet via scapy.
    You can use that as an inspiration for your own idea.

    Btw: The pylinter in vscode does sometimes not recognize scapy code.
    Do not get confused by that.
    You can circumvent that by inserting the specific path to the libary, like following:
    'from scapy.layers.tftp import TFTP' instead of 'from scapy.all import *'
    """
    packet = IP() / UDP() / TFTP() / TFTP_RRQ()
    packet[IP].dst = "192.168.30.90"
    packet[IP].src = "192.168.30.80"
    packet[UDP].sport = 69
    packet[UDP].dport = 69
    packet[TFTP].op = 1
    packet[TFTP_RRQ].filename = b"test511.txt"
    packet[TFTP_RRQ].mode = b"netascii"
    send(packet, iface="enp0s3.30")


def handle_normal_transmission(
    proxy: Proxy,
    initial_proxy_socket: socket,
    proxy_to_server_socket: socket,
    proxy_to_client_socket: socket,
) -> None:
    """The normal transmission without 'faulty situations' is handled here.

    Args:
        proxy (Proxy): proxy
        initial_proxy_socket (socket): socket for incomming requests of the client to the proxy
        proxy_to_server_socket (socket): socket for forwarding messages from the client to the server
        proxy_to_client_socket (socket): socket for forwarding messages from the server to the client
    """
    reset = False  # a boolean variable used for resetting the connection
    connected = False  # a boolean variable for checking the connection status
    last_ack = -1  # a variable for saving the last received ack
    last_block = -1  # a variable for saving the last block number of a data packet
    server_address = (SERVER_IP, TFTP_PORT)

    while True:
        if reset:
            server_address = (SERVER_IP, TFTP_PORT)
            reset = False
            connected = False
            last_ack = -1
            last_block = -1

        if connected:
            request, client_address = proxy.receive(proxy_to_client_socket)
        else:
            print("-" * 62)
            print("Waiting for the request from client.")
            print("-" * 62 + "\n")
            request, client_address = proxy.receive(initial_proxy_socket)
            connected = True

        if proxy.get_opcode(request) == OPCode.ACK.value:
            if proxy.get_blocknumber(request) == last_ack:
                reset = True
        elif proxy.get_opcode(request) == OPCode.DATA.value:
            if len(request) - 4 < 512:
                last_block = proxy.get_blocknumber(request)

        proxy.forward(proxy_to_server_socket, server_address, request)

        if not reset:
            response, server_address = proxy.receive(proxy_to_server_socket)
            if proxy.get_opcode(response) == OPCode.DATA.value:
                if len(response) - 4 < 512:
                    last_ack = proxy.get_blocknumber(response)
            elif proxy.get_opcode(response) == OPCode.ACK.value:
                if proxy.get_blocknumber(response) == last_block:
                    reset = True
            elif proxy.get_opcode(response) == OPCode.ERROR.value:
                reset = True

            proxy.forward(proxy_to_client_socket, client_address, response)


def main() -> None:
    """The main is creating a proxy instance and is calling the function
    which is responsible for the faulty situation
    """
    proxy = Proxy()
    initial_proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    initial_proxy_socket.bind((PROXY_IP_CLIENTSIDE, TFTP_PORT))
    proxy_to_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    proxy_to_server_socket.setsockopt(
        socket.SOL_SOCKET, 25, str("enp0s3.30" + "\0").encode("ascii")
    )
    proxy_to_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    num = read_user_input()
    print("Start of transmission.")
    if num == 0:
        handle_normal_transmission(
            proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket
        )
    elif num == 1:
        send_increased_payload_rrq(
            proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket
        )
    elif num == 2:
        handle_modified_bn_transmission(
            proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket
        )
    elif num == 3:
        handle_delayed_transmission(
            proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket
        )
    elif num == 4:
        handle_largefile_delayed_ack(
            proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket
        )
    elif num == 5:
        handle_error_packet_transmission(
            proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket
        )
    elif num == 6:
        delay_last_data_packet(
           proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket 
        )
    elif num == 7:
         send_ack_even_though_datapacket_not_forwarded_rrq(
           proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket  
         )

    print("End of transmission. \n")


def read_user_input() -> int:
    """Reads user input from the command line

    Returns:
        int: return the userinput if it was meaningful
    """
    is_valid_input = False
    while not is_valid_input:
        print("Which faulty-situation would you like to use for the next transmission?")
        print("0: Normal transmission")
        print("1: Increase Payload size of the data packet to over 512 bytes in RRQ/WRQ traffic")
        print("2: Change BN of ACK packet in RRQ/WRQ traffic")
        print("3: Transmission delay for data packet for 25 seconds in RRQ traffic")
        print("4: Request a file larger than 512 bytes and delay the ACK packet for 25 seconds in RRQ traffic")
        print("5: Replace a data packet with an error packet in WRQ traffic")
        print("6: faulty situation 6")
        print("7: Manipulate the checksum of a tftp ACK packet in RRQ using python Scapy")
        print("Enter option below:")  # prints empty line on console

        try:
            # Asking for user input
            user_input = int(input())
        except Exception:
            print("Please enter a number. Try again.")

        if user_input == 0:
            print("Normal transmission was selected")
            is_valid_input = True
        elif user_input == 1:
            print("Increased payload was selected")
            is_valid_input = True
        elif user_input == 2:
            print("Modify blocknumber was selected")
            is_valid_input = True
        elif user_input == 3:
            print("Transmission delay was selected")
            is_valid_input = True
        elif user_input == 4:
            print("Request of over 512 bytes was selected")
            is_valid_input = True
        elif user_input == 5:
            print("Replace datapacket with error packet was selected")
            is_valid_input = True
        elif user_input == 6:
            print("faulty situation 6 was selected")
            is_valid_input = True
        elif user_input == 7:
            print("Manipulation of checksum was selected")
            is_valid_input = True
        else:
            print("The number does not exist. Try again.")

    return user_input

# FAULTY SITUATIONS STARTS HERE

# Function for faulty situation 1 - Increase payload size to over 512 bytes
def send_increased_payload_rrq(
    proxy: Proxy,
    initial_proxy_socket: socket.socket,
    proxy_to_server_socket: socket.socket,
    proxy_to_client_socket: socket.socket) -> None:

    server_address = (SERVER_IP, TFTP_PORT)
   
    # RRQ Paket
    rrq_packet, client_address = proxy.receive(initial_proxy_socket)
    proxy.forward(proxy_to_server_socket, server_address, rrq_packet)

    # DATA packet containing 512 bytes
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    proxy.forward(proxy_to_client_socket, client_address, data_packet)

    # ACK packet with blocknummer 1
    ack_packet, client_address = proxy.receive(proxy_to_client_socket)
    proxy.forward(proxy_to_server_socket, server_address, ack_packet)
    
    # DATA packet containing 1 byte 
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    proxy.forward(proxy_to_client_socket, client_address, data_packet)
    
    # ACK packet with blocknumber 2 
    ack_packet, client_address = proxy.receive(proxy_to_client_socket)
    proxy.forward(proxy_to_server_socket, server_address, ack_packet)


# Function for faulty situation 2 - Change BN of ACK packet in RRQ/WRQ traffic
def handle_modified_bn_transmission(
    proxy: Proxy,
    initial_proxy_socket: socket.socket,
    proxy_to_server_socket: socket.socket,
    proxy_to_client_socket: socket.socket) -> None:

    server_address = (SERVER_IP, TFTP_PORT)
     
     # RRQ packet
    rrq_packet, client_address = proxy.receive(initial_proxy_socket)
    proxy.forward(proxy_to_server_socket, server_address, rrq_packet)

    # DATA packet containing 512 bytes
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    proxy.forward(proxy_to_client_socket, client_address, data_packet)

    # ACK packet with Blocknumber 1
    ack_packet, client_address = proxy.receive(proxy_to_client_socket)
    # Manipulate ack packet
    manipulated_ack = bytearray(ack_packet) # only bytearray is changeable
    manipulated_ack[3] = 9
    proxy.forward(proxy_to_server_socket, server_address, manipulated_ack)
    
    # DATA packet containing 1 byte
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    proxy.forward(proxy_to_client_socket, client_address, data_packet)

    # ACK packet with Blocknumber 2
    ack_packet, client_address = proxy.receive(proxy_to_client_socket)
    proxy.forward(proxy_to_server_socket, server_address, ack_packet)
 
 
# Function for faulty situation 3 - Transmission delay for datapacket with 25 seconds in RRQ traffic
def handle_delayed_transmission(
    proxy: Proxy,
    initial_proxy_socket: socket.socket,
    proxy_to_server_socket: socket.socket,
    proxy_to_client_socket: socket.socket) -> None:

    server_address = (SERVER_IP, TFTP_PORT)
    
    # RRQ packet
    rrq_packet, client_address = proxy.receive(initial_proxy_socket)
    proxy.forward(proxy_to_server_socket, server_address, rrq_packet)

    # DATA packet containing 512 bytes  
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    proxy.forward(proxy_to_client_socket, client_address, data_packet)

    # ACK packet with Blocknumber 1
    ack_packet, client_address = proxy.receive(proxy_to_client_socket)
    proxy.forward(proxy_to_server_socket, server_address, ack_packet)
    
    # DATA packet containing 1 byte
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    # Set a delay of 25 seconds before forwarding the data packet to the client
    time.sleep(25)
    proxy.forward(proxy_to_client_socket, client_address, data_packet)

    # ACK packet with Blocknumber 2
    ack_packet, client_address = proxy.receive(proxy_to_client_socket)
    proxy.forward(proxy_to_server_socket, server_address, ack_packet)



# Function for faulty situation 4 - Request a file larger than 512 bytes and delay ACK packet
def handle_largefile_delayed_ack(
    proxy: Proxy,
    initial_proxy_socket: socket.socket,
    proxy_to_server_socket: socket.socket,
    proxy_to_client_socket: socket.socket) -> None:
    server_address = (SERVER_IP, TFTP_PORT)
    
    # RRQ packet
    rrq_packet, client_address = proxy.receive(initial_proxy_socket)
    proxy.forward(proxy_to_server_socket, server_address, rrq_packet)
    
    # DATA packet containing 512 bytes  
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    proxy.forward(proxy_to_client_socket, client_address, data_packet)
    
    # ACK packet with Blocknumber 1
    ack_packet, client_address = proxy.receive(proxy_to_client_socket)
    time.sleep(25)
    proxy.forward(proxy_to_server_socket, server_address, ack_packet)
    
    # DATA packet containing 1 byte
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    proxy.forward(proxy_to_client_socket, client_address, data_packet)
    
    # ACK packet with Blocknumber 2
    ack_packet, client_address = proxy.receive(proxy_to_client_socket)
    proxy.forward(proxy_to_server_socket, server_address, ack_packet)
    
    
    
# Function for faulty situation 5 - Replace a data packet with an error packet in WRQ traffic
def handle_error_packet_transmission(
    proxy: Proxy,
    initial_proxy_socket: socket.socket,
    proxy_to_server_socket: socket.socket,
    proxy_to_client_socket: socket.socket) -> None:
    
    server_address = (SERVER_IP, TFTP_PORT)
    
    # WRQ packet
    WRQ_packet, client_address = proxy.receive(initial_proxy_socket)
    proxy.forward(proxy_to_server_socket, server_address, WRQ_packet)
    
    # ACK packet from server
    ack_packet, server_address = proxy.receive(proxy_to_server_socket)
    proxy.forward(proxy_to_client_socket, client_address, ack_packet)
    
    # DATA packet from client
    data_packet, client_address = proxy.receive(proxy_to_client_socket)
    proxy.forward(proxy_to_server_socket, server_address, data_packet)
    
    # ACK packet from server
    ack_packet, server_address = proxy.receive(proxy_to_server_socket)
    proxy.forward(proxy_to_client_socket, client_address, ack_packet)
    
    # Data packet from server 
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    
    # Create an error packet instead of forwarding the last data packet
    error_opcode = OPCode.ERROR.value.to_bytes(2, 'big')
    error_code = (4).to_bytes(2, 'big')
    error_msg = b'This is just a simulated error'
    error_packet = error_opcode + error_code + error_msg + b'\x00'
    
    # Forward the error packet to the client instead of the last data packet
    proxy.forward(proxy_to_client_socket, client_address, error_packet)
    
    # ACK packet from client
    ack_packet, client_address = proxy.receive(proxy_to_client_socket)
    proxy.forward(proxy_to_server_socket, server_address, ack_packet)
    
    
 
#Faulty situation 6 (IN PROGRESS)     
def delay_last_data_packet(
    proxy: Proxy,
    initial_proxy_socket: socket.socket,
    proxy_to_server_socket: socket.socket,
    proxy_to_client_socket: socket.socket) -> None:
    
    server_address = (SERVER_IP, TFTP_PORT)
    
    # RRQ packet
    rrq_packet, client_address = proxy.receive(initial_proxy_socket)
    proxy.forward(proxy_to_server_socket, server_address, rrq_packet)
    
    # DATA packet containing 512 bytes  
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    proxy.forward(proxy_to_client_socket, client_address, data_packet)
    
    # ACK packet with Blocknumber 1
    ack_packet, client_address = proxy.receive(proxy_to_client_socket)
    proxy.forward(proxy_to_server_socket, server_address, ack_packet)
    
    # DATA packet containing 1 byte (pretending this is the last data packet)
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    
    # Delay transmission of last data packet by 15 seconds
    time.sleep(15)
    proxy.forward(proxy_to_client_socket, client_address, data_packet)
    
    # ACK packet with Blocknumber 2
    ack_packet, client_address = proxy.receive(proxy_to_client_socket)
    proxy.forward(proxy_to_server_socket, server_address, ack_packet)    
    
    

#Function for faulty situation 7 - Manipulate the checksum of a tftp ACK packet in RRQ using python Scapy
def send_ack_even_though_datapacket_not_forwarded_rrq(
    proxy: Proxy,
    initial_proxy_socket: socket.socket, 
    proxy_to_server_socket: socket.socket, 
    proxy_to_client_socket: socket.socket) -> None:
    
    server_address = (SERVER_IP, TFTP_PORT)
    
    # RRQ Packet
    rrq_packet, client_address = proxy.receive(initial_proxy_socket)
    proxy.forward(proxy_to_server_socket, server_address, rrq_packet)

    # DATA packet containing 512 bytes
    data_packet, server_address = proxy.receive(proxy_to_server_socket)
    
    # Do not forward the data packet to the client
    # proxy.forward(proxy_to_client_socket, client_address, data_packet)  # This line is commented out
    
    # Send an ACK packet to the server instead
    block_number = 1
    ack_packet = b'\x00\x04' + block_number.to_bytes(2, 'big')  # TFTP ACK packet format
    proxy.forward(proxy_to_server_socket, server_address, ack_packet)



if __name__ == "__main__":
    main()
