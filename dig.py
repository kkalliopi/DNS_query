import socket
from struct import pack, unpack, calcsize
import random
from io import BytesIO
import sys


def make_question_header(query_id):

  header = pack('>HHHHHH',query_id, 0x0100, 0x0001, 0x0000, 0x0000, 0x0000)

  return header

def encode_domain_name(domain):

  translated_name =''.join(map(lambda x: chr(len(x)) + x, domain.split('.'))) + '\0'
  bytes_s = translated_name.encode("utf-8")
  return bytes_s


def make_dns_query(domain, type):

  query_id = random.randint(0,65535)
  header = make_question_header(query_id)
  question =  encode_domain_name(domain)

  encoded_question = question + pack(">HH", type, 1)

  return header + encoded_question

class DNSHeader:

    def __init__(self,buf):

        self.buf = buf
        self.id, self.flags, self.num_questions, self.num_answers, self.num_auth, self.num_additionals = unpack('>HHHHHH', buf.read(12))


TYPES = { 1:"A", 2: "NS", 5: "CNAME"}


class DNSRecord:

  def __init__(self,buf):

      self.buf = buf
      self.name = read_domain_name(buf)
      self.type, self.cls, self.ttl, self.rdlength = unpack('>HHHH', buf.read(8))
      self.read_rdata(buf,self.rdlength)
      self.to_s()


  def read_rdata(self,buf, length):

     for self.type in TYPES:
         if TYPES[self.type] == "CNAME" or TYPES[self.type] == "NS":
             return(read_domain_name(buf))
         elif TYPES[self.type] == "A":
             bytes =  buf.read(length)
             tuple_of_bytes = unpack('B' * len(bytes), bytes)[-4:]
             self.ip_address = '.'.join(map(str, tuple_of_bytes))
             return self.ip_address

         else:
             rdata_0 = buf.read(length)
             return(rdata_0)

  def to_s(self):
      return (f"{self.name}\t\t{self.ttl}\t{TYPES[self.type]}\t{self.ip_address}")


def read_domain_name(buf):

      domain = []
      while True:
          byte = buf.read(1)
          length = unpack('B', byte)[0]
          if length == 0:
              break
          elif length & 0b11000000 == 0b11000000:
              second_byte = buf.read(1)
              second_byte_unpacked = unpack('B', second_byte)[0]
              offset = ((length & 0x3f) << 8) + second_byte_unpacked
              old_pos = buf.seek(1)
              buf.seek(offset)
              string = read_domain_name(buf)
              for character in string:
                  domain.append(ord(character))
              buf.seek(old_pos)
              break
          else:
             domain.append(length)

      result = ''.join(map(chr, domain))
      return result


class DNSQuery:

  def __init__(self,buf):


      self.buf = buf
      self.domain = read_domain_name(buf)
      self.type, self.cls = unpack('>HH', buf.read(4))


class DNSResponse:

    def __init__(self, bytes):

        self.bytes = bytes
        buf = BytesIO(bytes)
        self.header = DNSHeader(buf)
        self.queries = []
        for query in range(0, self.header.num_questions):
            self.queries.append(DNSQuery(buf))
        self.answers = []
        for answer in range(0, self.header.num_answers):
            self.answers.append(DNSRecord(buf))
        self.authorities = []
        for auth in range(0, self.header.num_auth):
            self.answers.append(DNSRecord(buf))
        self.additionals = []
        for add in range(0, self.header.num_additionals):
            self.additionals.append(DNSRecord(buf))

def main():

    UDPsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDPsocket.bind(('0.0.0.0', 12345))
    UDPsocket.connect(('8.8.8.8', 53))
    domain = sys.argv[1]
    UDPsocket.send(make_dns_query(domain, 1), 0)
    receivedBytes, address = UDPsocket.recvfrom(1024)
    response  = DNSResponse(receivedBytes)

    
    for answer in response.answers:
        print(answer.to_s())

main()
