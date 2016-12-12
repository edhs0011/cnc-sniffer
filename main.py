import socket
import sys
import struct
import threading

class Conection:
    def __init__(self, server):
        self.addr = server[0]
        self.port = server[1]
        self.atk_dict = dict()
        self.atk_dict["cnc"] = self.addr

    def run(self):
        # Create a TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        server_address = (self.addr, self.port)
        print >>sys.stderr, 'connecting to %s port %s' % server_address
        self.sock.connect(server_address)

        try:
            # Send data
            print >>sys.stderr, 'sending'
            self.sock.sendall(b'\x00\x00\x00\x01')
            self.sock.sendall(b'\x00')

            while True:
                self.parse_attack()

        finally:
            print >>sys.stderr, 'closing socket'
            self.sock.close()

    def read_int_from_bytes(self, bytes):
        data = self.sock.recv(bytes)
        if bytes == 1:
            return struct.unpack("!H", "\x00"+data)[0]
        elif bytes == 2:
            return struct.unpack("!H", data)[0]
        else:
            return struct.unpack("!I", data)[0]

    def read_ip_from_bytes(self):
        data = self.sock.recv(4)
        data = [d for d in data]
        data = map(lambda x: "\x00"+x, data)
        data = reduce(lambda x, y: x+y, data)
        return struct.unpack("!HHHH", data)

    def parse_attack(self):
        pkg_len = self.read_int_from_bytes(2)
        self.atk_dict["pkg_len"] = pkg_len
        print "total len %d" % pkg_len

        atk_duration = self.read_int_from_bytes(4)
        self.atk_dict["atk_duration"] = atk_duration
        print "duration %d" % atk_duration

        atk_id = self.read_int_from_bytes(1)
        self.atk_dict["atk_id"] = atk_id
        print "attack ID %d" % atk_id

        atk_target = self.read_int_from_bytes(1)
        self.atk_dict["atk_target"] = atk_target
        print "target %d" % atk_target

        # read IP
        atk_ip = map(lambda x: str(x), self.read_ip_from_bytes())
        print "IP"
        print atk_ip

        # IP mask
        atk_ip_mask = self.read_int_from_bytes(1)
        print "IP mask %d" % atk_ip_mask

        self.atk_dict["atk_ip"] = "{0}/{1}".format(".".join(atk_ip), atk_ip_mask)

        # opt len
        atk_opt_len = self.read_int_from_bytes(1)
        print "opt len %d" % atk_opt_len

        atk_opt = []
        for i in range(atk_opt_len):
            atk_opt_key = self.read_int_from_bytes(1)
            print "opt key %d" % atk_opt_key

            opt_val_len = self.read_int_from_bytes(1)
            print "opt val len %d" % opt_val_len

            atk_opt_data = self.sock.recv(opt_val_len)
            print bytes.decode(atk_opt_data)

            atk_opt.append((atk_opt_key, atk_opt_data))

        self.atk_dict["atk_opt"] = atk_opt
        print self.atk_dict

def sniffer(cnc_servers):
    for server in cnc_servers:
        conn = Conection(server)
        thd = threading.Thread(target=conn.run)
        thd.daemon = True
        thd.start()

def main():
    cnc_servers = [
        ("35.162.249.35", 23),
        ("35.162.249.35", 23)
    ]
    sniffer(cnc_servers)
    while True:
        pass

if __name__=='__main__':
    main()