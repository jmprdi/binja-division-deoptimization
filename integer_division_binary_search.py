import ctypes

def equ_test(x):
    q = x // 53
    return q

def int_div_test(equation, val):
    r1 = equation(val)
    r2 = equation(val - 1)
    if r1 == 1 and r2 == 0:
        return 0
    elif r1 >= 1:
        return 1
    else:
        return -1

def integer_division_binary_search(equation, size):
    """
    Find the divisor of an integer division equation via a binary search.

    :equation: Equation to test
    :size: Maximum size of divisor
    """

    i = size // 2
    move_amount = i
    done = False
    while not done:
        tst = int_div_test(equation, i)
        if tst == 0:
            return i
        elif tst > 0:
            move_amount //= 2
            i = i - move_amount
        elif tst < 0:
            move_amount //= 2
            i = i + move_amount

        if move_amount == 0:
            raise Exception("INTEGER DIVISION BINARY SEARCH FAIL")

if __name__ == '__main__':
    print(integer_division_binary_search(equ_test, 2 ** 31))
