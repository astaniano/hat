# look at this gist: https://gist.github.com/Paradoxis/6336c2eaea20a591dd36bb1f5e227da2
# and this stackoverflow: https://stackoverflow.com/questions/67629248/how-do-i-urlencode-all-the-characters-in-a-string-including-safe-characters

import sys

def encode_all(to_be_encoded):
    return "".join("%{0:0>2x}".format(ord(char)) for char in to_be_encoded)

print(encode_all(sys.argv[1]))


# Explanation:
# The first thing to notice is that the return value is a generator expression (... for char in string) wrapped in a str.join call ("".join(...)). This means we will be performing an operation for each character in the string, then finally joining each outputted string together (with the empty string, "").
# 
# The operations performed per character can be broken down into the following:
# 
#     ord(char): Convert each character to the corresponding number.
#     "%{0:0>2x}".format(...): Convert the number to a hexadecimal value. Then, format the hexadecimal value into a string (with a prefixed "%").
# 
# When you look at the whole function from an overview, it is converting each character to a number, converting that number to hexadecimal, then jamming all the hexadecimal values into a string (which is then returned).


