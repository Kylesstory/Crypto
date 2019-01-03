### referred to Märt Bakhoff
### https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        return -1 # slightly modified here from original program
    else:
        return x % m