from binaryninja import LowLevelILOperation, interaction


class InvalidPatternError(Exception):
    pass


def validate_pattern(operations: list, instructions: list, starting_index: int):
    """
    Check if a pattern is valid.

    :operations: List of the operations in the pattern. LLIL_SET_REG is assumed.
    :instructions: List of instructions to test
    :starting_index: Index to test at
    """
    retvals = []
    for i, operation in enumerate(operations):
        try:
            if not (
                instructions[starting_index + i].operation
                == LowLevelILOperation.LLIL_SET_REG
                and instructions[starting_index + i].operands[1].operation == operation
            ):
                raise InvalidPatternError
            else:
                retvals.append(
                    instructions[starting_index + i].operands[1].operands[1].value.value
                )
        except IndexError:
            raise InvalidPatternError

    return retvals


def signed_division_pattern_1(instructions, starting_index):
    """
    eax = dividend // dividend
    rdx = sx.q(eax)
    rdx = rdx * 0x323c91c5
    rdx = rdx u>> 0x20
    edx = edx s>> 0x1b
    eax = eax s>> 0x1f
    edx = edx - eax
    eax = edx // quotient = dividend / 683958287
    """
    operations = [
        LowLevelILOperation.LLIL_MUL,
        LowLevelILOperation.LLIL_LSR,
        LowLevelILOperation.LLIL_ASR,
        LowLevelILOperation.LLIL_ASR,
    ]
    try:
        c, x, z, y = validate_pattern(operations, instructions, starting_index)

        # https://zneak.github.io/fcd/2017/02/19/divisions.html
        denominator = round((2 ** (x + y + z)) / (c * (2 ** y - 1) + 2 ** z))

        return denominator
    except InvalidPatternError:
        return None


def annotate_divisions(bv, func):
    instructions = [x for x in func.llil.instructions]
    found = False
    for i in range(len(instructions) - 4):
        divisor = signed_division_pattern_1(instructions, i)
        if divisor is not None:
            bv.set_comment_at(instructions[i].address, "divide by " + str(divisor))
            found = True

    if not found:
        interaction.show_message_box(
            "Deoptimize Division", "No divisions found in current function"
        )
