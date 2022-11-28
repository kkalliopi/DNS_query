domain = [7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109]


def domain_decode(domain):
    i = 0
    list = []
    while i < len(domain):

        length = domain[i]
        list.append(domain[i+1 :i+length+1])
        i = i+ length + 1

    return ".".join(map(lambda x:''.join(map(chr, x)), list))

print(domain_decode(domain))
