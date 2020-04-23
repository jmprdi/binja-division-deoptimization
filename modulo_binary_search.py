import ctypes


def mod_test(equation, val):
    """
    Comparison for the modulo binary search.

    :equation: Equation to test
    :val: Input to the division
    """

    r1 = equation(val)
    if r1 == None:
        return None
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
        if tst == None:
            return None
        if tst == 0:
            result = equation(i - 1) + 1
            if result == 1:
                return None
            # Test that it is actually a modulo
            if (i - 1 + result) % result != result - 1:
                return None
            if (i - 2 + result) % result != equation(i - 2):
                return None
            return result
        elif tst > 0:
            move_amount //= 2
            i = i - move_amount
        elif tst < 0:
            move_amount //= 2
            i = i + move_amount

        if move_amount == 0:
            return None


def equ_test(x):
    q = x % 1337
    return q


if __name__ == "__main__":
    print(modulo_binary_search(equ_test, 2 ** 32))
