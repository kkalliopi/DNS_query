import socket
from struct import pack, unpack
import random
from io import BytesIO
import sys

def make_question_header(query_id):

  header = pack('>HHHHHH',query_id, 0x0100, 0x0001, 0x0000, 0x0000, 0x0000)
  return header

def encode_domain_name(domain):

  elements_of_domain = domain.split(".")
  lenght_of_elements = list(map(len,elements_of_domain))
  merged_list = [element for pair in zip(lenght_of_elements, elements_of_domain + [0])
                            for element in pair]

  x = "".join(map(str, merged_list))
  translated_name = " ".join(x) + "\0"
  return translated_name

def make_dns_query(domain, type):

  query_id = random.randint(0,65535)
  header = make_question_header(query_id)
  question =  encode_domain_name(domain)
  list = [ord(char) for char in question]
  encoded_question = pack(">{}HHH".format(len(list)), *list, type, 1)

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
      self.rdata = read_rdata(buf,self.rdlength)
      self.repr = to_s()

  def read_rdata(self, buf, length):
     self.type = type_name
     for type_name in TYPES:
         if TYPES[type_name] == "CNAME" or TYPES[type_name] == "NS":
             return(read_domain_name(buf))
         elif TYPES[type_name] == "A":
             rdata_a = unpack('C*',buf.read(length)).join('.')
             return(rdata_a)
         else:
             rdata_0 = buf.read(length)
             return(rdata_0)

  def to_s():
     return(f"{self.name}\t\t{self.ttl}\t{type_name}\t{self.rdata}")

def read_domain_name(buf):

      domain = []
      while True:
          len_bytes = buf.read(1)
          len = unpack('B', len_bytes)[0]
          if len == 0:
              break
          elif len & 0b11000000 == 0b11000000:
              second_byte = buf.read(1)
              second_byte_unpacked = unpack('B', second_byte)[0]
              offset = ((len & 0x3f) << 8) + second_byte_unpacked
              old_pos = buf.seek(1)
              buf.seek(offset)
              domain.append(read_domain_name(buf))
              buf.seek(old_pos)
              break
          else:
             domain.append(len)

      result = '.'.join(map(str, domain))
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
    print(len(receivedBytes))
    response  = DNSResponse(receivedBytes)
    for answer in response.answers:
        print(answer, end =" ")

main()
