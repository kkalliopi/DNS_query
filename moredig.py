import socket
from struct import pack, unpack, calcsize
import random
from io import BytesIO
import sys

def encode_domain_name(domain):
  translated_name =''.join(map(lambda x: chr(len(x)) + x, domain.split('.'))) + '\0'
  bytes_s = translated_name.encode("ascii")

  return bytes_s

print(encode_domain_name('example.com') == bytes([0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0]))






def make_question_header(query_id):

  header = pack('>HHHHHH',query_id, 0x0100, 0x0001, 0x0000, 0x0000, 0x0000)
  return header

hex_string = "b96201000001000000000000"
bytes0 = bytes.fromhex(hex_string)


print(make_question_header(0xb962) == bytes0)





def make_dns_query(domain, type):
  query_id = random.randint(0,65535)
  header = make_question_header(0xb962)
  question =  encode_domain_name(domain)

  encoded_question = question + pack(">HH", type, 1)

  return  encoded_question

print(make_dns_query('example.com', 1) == bytes([ 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01]))




bytes_response0 = b'dV\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"'
buf0 = BytesIO(bytes_response0)

def dnsheader(buf):


        id, flags, num_questions, num_answers, num_auth, num_additionals = unpack('>HHHHHH', buf.read(12))
        return (id, flags, num_questions, num_answers, num_auth, num_additionals)
print(dnsheader(buf0) == (25686, 33152, 1 ,1 ,0 ,0))





bytes_response1 = b'\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00Dl\x00\x04]\xb8\xd8"'
buf1 = BytesIO(bytes_response1)

def read_domain_name(buf):
      domain = []

      while True:
          byte = buf.read(1)
          int_char = unpack('B', byte)[0]
          if int_char == 0:
              break
          elif int_char & 0b11000000 == 0b11000000:

              second_byte = buf.read(1)
              second_byte_unpacked = unpack('B', second_byte)[0]
              offset = ((int_char & 0x3f) << 8) + second_byte_unpacked
              old_pos = buf.seek(1)
              buf.seek(offset)
              domain.append(read_domain_name(buf))
              buf.seek(old_pos)
              break
          else:
             domain.append(int_char)

      if all(isinstance(item, int) for item in domain):
          i = 0
          list = []
          while i < len(domain):
              length = domain[i]
              list.append(domain[i+1 :i+length+1])
              i = i+ length + 1

          return ".".join(map(lambda x:''.join(map(chr, x)), list))
      else:
           return "".join(domain)


print(read_domain_name(buf1) == "example.com")






bytes_response2 = b'\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00Dl\x00\x04]\xb8\xd8"'
buf2 = BytesIO(bytes_response2)

def dnsrecord(buf):

     type, cls, ttl, rdlength = unpack('>HHHH', buf.read(8))
     return read_rdata(buf,rdlength)

TYPES = { 1:"A", 2: "NS", 5: "CNAME"}

def read_rdata(buf, length):

   for type in TYPES:

       if TYPES[type] == "A":

           bytes =  buf.read(length)
           tuple_of_bytes = unpack('B' * len(bytes), bytes)[-4:]
           ip_address = '.'.join(map(str, tuple_of_bytes))

           return ip_address

       else:
           rdata_0 = buf.read(length)
           return(rdata_0)


print(dnsrecord(buf2) == '93.184.216.34')







bytes_response3 = b'\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00Dl\x00\x04]\xb8\xd8"'
buf3 = BytesIO(bytes_response3)


def dnsquery(buf):


     domain = read_domain_name(buf)
     type, cls = unpack('>HH', buf.read(4))
     return (type, cls)

print(dnsquery(buf3) == (1,1))
