import socket
import sys
import struct
import threading
import re
import time
import binascii
import logging
FORMAT = "%(asctime)-15s %(levelname)-8s %(message)s"
log_file = "/var/log/cnc-sniffer/cnc.log"
logging.basicConfig(level=logging.DEBUG, format=FORMAT)
fileHandler = logging.FileHandler(log_file, mode='a')
logger = logging.getLogger(__name__)
logger.addHandler(fileHandler)

class Conection:
    def __init__(self, server):
        self.addr = server[0]
        self.port = server[1]
        self.atk_dict = dict()
        self.buf_size = 1024
        self.buf = ""

    def run(self):
        m = re.match('[0-9].[0-9].[0-9].[0-9]', self.addr)
        if m is not None:
            self.domain = ""
        else:
            self.domain = self.addr
            while True:
                try:
                    self.addr = socket.gethostbyname(self.addr)
                    break
                except:
                    time.sleep(5)
                    logger.debug("retry to get the IP from DNS %s" % self.addr)
                    continue

        self.atk_dict["cnc"] = self.addr
        self.atk_dict["domain"] = self.domain

        while True:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_address = (self.addr, self.port)
                logger.debug('connecting to %s port %s' % server_address)
                self.sock.connect(server_address)
                # Send data
                logger.info('successfully connected to CNC: %s (%s)' % (self.addr, self.domain))
                self.sock.sendall(b'\x00\x00\x00\x01')
                self.sock.sendall(b'\x00')

                while True:
                    self.buf = self.sock.recv(self.buf_size)
                    logger.info("recieve data from %s : %s" % 
                        (self.addr, ' '.join(map(lambda y: '\\x'+y, [binascii.hexlify(i) for i in self.buf]))))
                    self.parse_attack()

            except socket.error, msg:
                time.sleep(5)
                logger.error(msg)
                logger.error("reconnect to the CNC server %s" % self.addr)
                continue
            except Exception as e:
                if hasattr(e, 'message'):
                    print(e.message)
                else:
                    print(e)
                time.sleep(5)
                continue
            finally:
                logger.debug('closing socket')
                self.sock.close()

    def read_int_from_bytes(self, bytes):
        data = self.buf[:bytes]
        self.buf = self.buf[bytes:]
        if bytes == 1:
            return struct.unpack("!H", "\x00"+data)[0]
        elif bytes == 2:
            return struct.unpack("!H", data)[0]
        else:
            return struct.unpack("!I", data)[0]

    def read_ip_from_bytes(self):
        data = self.buf[:4]
        self.buf = self.buf[4:]
        data = [d for d in data]
        data = map(lambda x: "\x00"+x, data)
        data = reduce(lambda x, y: x+y, data)
        return struct.unpack("!HHHH", data)

    def parse_attack(self):
        pkg_len = self.read_int_from_bytes(2)
        self.atk_dict["pkg_len"] = pkg_len
        logger.debug("total len %d" % pkg_len)

        atk_duration = self.read_int_from_bytes(4)
        self.atk_dict["atk_duration"] = atk_duration
        logger.debug("duration %d" % atk_duration)

        atk_id = self.read_int_from_bytes(1)
        self.atk_dict["atk_id"] = atk_id
        logger.debug("attack ID %d" % atk_id)

        atk_target = self.read_int_from_bytes(1)
        self.atk_dict["atk_target"] = atk_target
        logger.debug("target %d" % atk_target)

        # read IP
        atk_ip = map(lambda x: str(x), self.read_ip_from_bytes())
        logger.debug(atk_ip)

        # IP mask
        atk_ip_mask = self.read_int_from_bytes(1)
        logger.debug("IP mask %d" % atk_ip_mask)

        self.atk_dict["atk_ip"] = "{0}/{1}".format(".".join(atk_ip), atk_ip_mask)

        # opt len
        atk_opt_len = self.read_int_from_bytes(1)
        logger.debug("opt len %d" % atk_opt_len)

        atk_opt = []
        for i in range(atk_opt_len):
            atk_opt_key = self.read_int_from_bytes(1)
            logger.debug("opt key %d" % atk_opt_key)

            opt_val_len = self.read_int_from_bytes(1)
            logger.debug("opt val len %d" % opt_val_len)

            atk_opt_data = self.buf[:opt_val_len]
            self.buf = self.buf[opt_val_len:]
            logger.debug(bytes.decode(atk_opt_data))

            atk_opt.append((atk_opt_key, atk_opt_data))

        self.atk_dict["atk_opt"] = atk_opt
        logger.info(self.atk_dict)

def sniffer(cnc_servers):
    for server in cnc_servers:
        conn = Conection(server)
        thd = threading.Thread(target=conn.run)
        thd.daemon = True
        thd.start()

def main():
    cnc_servers = [
        ("network.santasbigcandycane.cx", 23),
        ("cnc.disabled.racing", 23),
        ("gay.disabled.racing", 23),
        ("penis.disabled.racing", 23),
        ("b0ts.xf0.pw", 23),
        ("swinginwithme.ru", 23),
        ("imscaredaf.xyz", 23),
        ("kankerc.queryhost.xyz", 23),
        ("meme.icmp.online", 23),
        ("our.bklan.ru", 23),
        ("heis.lateto.work", 23),
        ("mufoscam.org", 23),
        ("netwxrk.org", 23),
        ("q5f2k0evy7go2rax9m4g.ru", 23),
        ("check.securityupdates.us", 23),
        ("cnc.routersinthis.com", 23),
        ("dongs.disabled.racing", 23),
        ("dongs.icmp.online", 23),
        ("ftp.timeserver.host", 23),
        ("ftp.xenonbooter. xyz", 23),
        ("hightechcrime.club", 23),
        ("irc.xf0.pw", 23),
        ("listen.routersinthis.com", 23),
        ("listen.xenonbooter.xyz", 23),
        ("loadsecure.pw", 23),
        ("lol.disabled.racing", 23),
        ("timeserver.host", 23),
        ("tr069.online", 23),
        ("www.mufoscam.org", 23)
    ]
    sniffer(cnc_servers)
    while True:
        fileHandler = logging.FileHandler(log_file, mode='a')
        pass

if __name__=='__main__':
    main()
