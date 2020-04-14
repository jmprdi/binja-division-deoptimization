import ctypes
def equ_test(x):
    q = x % 1337
    return q

def mod_test(equation, val):
    # TODO: 1 and -1 are lower / higher currently,
    r1 = equation(val)
    if r1 == 0:
        return 0
    elif r1 != val:
        return 1
    elif r1 == val:
        return -1

def modulo_binary_search(equation, size):
    """
    Find the modulo of an equation via a binary search.

    :equation: Equation to test
    :size: Maximum size of modulo
    """

    i = size // 2
    move_amount = i
    done = False
    while not done:
        tst = mod_test(equation, i)
        if tst == 0:
            return equation(i - 1) + 1
        elif tst > 0:
            move_amount //= 2
            i = i - move_amount
        elif tst < 0:
            move_amount //= 2
            i = i + move_amount

        if move_amount == 0:
            raise Exception("MODULO BINARY SEARCH FAIL")

if __name__ == '__main__':
    print(modulo_binary_search(equ_test, 2**32))
