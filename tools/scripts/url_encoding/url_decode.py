import sys
import urllib.parse

def url_decode(encoded_str):
    return urllib.parse.unquote(encoded_str)

if __name__ == "__main__":
    decoded_string = url_decode(sys.argv[1])
    print()
    print(decoded_string)
    print()

