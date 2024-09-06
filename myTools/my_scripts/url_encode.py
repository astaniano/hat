import sys
import urllib.parse

def encode(to_be_encoded):
    return urllib.parse.quote(to_be_encoded)

print(encode(sys.argv[1]))


