from Crypto.Util.number import  long_to_bytes

# Author: Harish Kommineni
# Date: November 20, 2016

# This method uses euclidean algorithm to find values values of a and b in e1*a + e2*b = gcd(e1,e2)
def extended_euclid(a, b):
    x, lastX = 0, 1
    y, lastY = 1, 0
    while (b != 0):
        q = a // b
        a, b = b, a % b
        x, lastX = lastX - q * x, x
        y, lastY = lastY - q * y, y
    return (lastX, lastY)

# This method returns the inverse for given values
def get_inverse(c, n):
    x = lasty = 0
    lastx = y = 1
    while n != 0:
        q = c // n
        c, n = n, c % n
        x, lastx = lastx - q * x, x
        y, lasty = lasty - q * y, y
    return lastx


def attack2():
    """ This is to implement the unpadded RSA attack when n, e1, e2, c1, c2 are known"""
    n=402394248802762560784459411647796431108620322919897426002417858465984510150839043308712123310510922610690378085519407742502585978563438101321191019034005392771936629869360205383247721026151449660543966528254014636648532640397857580791648563954248342700568953634713286153354659774351731627683020456167612375777
    e1=3

    c1=4020137574131575546540268502595841326627069047574502831387774931737219358054228401772587980633053000
    c2=170356929377044754324767086491413709789303946387160918939626824506821140429868670769571821346366209258416985269309515948776691067548265629489478628756185802183547222688698309731374342109385922509501909728895585636684978295199882599818258590851085977232207148101448845575681189389906429149193460620083999406237

    # convert given hexadecimal e2 to decimal
    e2 = int("0x10001", 16)
    print("e2 after converting to decimal: ", e2)

    a, b = extended_euclid(e1, e2)
    print("a = ", a, "b = ", b)

    # compute c2^-1 mod N
    inverse = get_inverse(c2, n)
    print("Inverse of c2 and n is: ", inverse)

    # compute message
    message = (pow(c1, a) * inverse) % n
    print 'Recovered: ', long_to_bytes(message)


# This is the main method to implement Week13 part-2 exercises.
if __name__ == '__main__':
    attack2()

