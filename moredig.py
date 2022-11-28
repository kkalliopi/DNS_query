

def encode_domain_name(domain):
  translated_name =''.join(map(lambda x: chr(len(x)) + x, domain.split('.'))) + '\0'
  bytes_s = translated_name.encode("ascii")
  return bytes_s

print(encode_domain_name('example.com') == bytes([0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0]))
