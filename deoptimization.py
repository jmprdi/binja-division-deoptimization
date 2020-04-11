from binaryninja import MediumLevelILOperation, interaction
from z3 import Real, BitVec, BitVecVal, ZeroExt, LShR, Extract, simplify, SignExt, Solver, sat, ForAll

debug = False

known_ssa_vars = {

}

# TODO: Better assign dividend
dividends = []

def get_definition(var, curr_ins, func):
    definition_instruction = func.mlil.ssa_form.get_ssa_var_definition(var)
    if definition_instruction:
        return definition_instruction
    else:
        return None

def perform_instruction(bv, func, ssa_instruction, depth):
    # Depth only decreases when resolving another register.

    instruction = ssa_instruction
    operands = instruction.operands
    operation = instruction.operation

    if debug:
        print("Performing {}".format(instruction))

    try:
        if ssa_instruction.value.is_constant:
            print("it simplified to {}".format(ssa_instruction.value.value))
            return ssa_instruction.value.value
    except:
        pass

    if operation == MediumLevelILOperation.MLIL_VAR_SSA:
        definition_instruction = get_definition(operands[0], ssa_instruction, func)
        if definition_instruction and depth > 0:
            return perform_instruction(bv, func, definition_instruction, depth - 1)
        else:
            name = repr(operands[0])
            size = operands[0].var.type.width
            r = Real(name)
            dividends.append(r)
            return r
    if operation == MediumLevelILOperation.MLIL_VAR_ALIASED:
        definition_instruction = get_definition(operands[0], ssa_instruction, func)
        if definition_instruction and depth > 0:
            return perform_instruction(bv, func, definition_instruction, depth - 1)
        else:
            name = repr(operands[0])
            size = operands[0].var.type.width
            r = Real(name)
            dividends.append(r)
            return r
    if operation == MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
        # TODO: Double check extract values
        # operand 0: offset
        # operand 1: reg
        # MAYBE
        definition_instruction = get_definition(operands[0], ssa_instruction, func)
        if definition_instruction and depth > 0:
            return perform_instruction(bv, func, definition_instruction, depth - 1)
        else:
            name = repr(operands[0])
            size = operands[0].var.type.width
            r = Real(name)
            dividends.append(r)
            return r
    elif operation == "": #MediumLevelILOperation.LLIL_CONST:
        # TODO: Figure out size thing; Shoul this be a bitvec?
        return operands[0]
    elif operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
        known_ssa_vars[instruction.dest] = perform_instruction(bv, func, operands[1], depth)
    elif operation == MediumLevelILOperation.MLIL_ASR:
        return perform_instruction(bv, func, operands[0], depth) / 2 ** perform_instruction(bv, func, operands[1], depth)
    elif operation == MediumLevelILOperation.MLIL_LSR:
        return perform_instruction(bv, func, operands[0], depth) / 2 ** perform_instruction(bv, func, operands[1], depth)
    elif operation == MediumLevelILOperation.MLIL_MUL:
        return perform_instruction(bv, func, operands[0], depth) * perform_instruction(bv, func, operands[1], depth)
    elif operation == MediumLevelILOperation.MLIL_SUB:
        return perform_instruction(bv, func, operands[0], depth) - perform_instruction(bv, func, operands[1], depth)
    elif operation == MediumLevelILOperation.MLIL_ADD:
        return perform_instruction(bv, func, operands[0], depth) + perform_instruction(bv, func, operands[1], depth)
    elif operation == MediumLevelILOperation.MLIL_ZX:
        # TODO: Size Check?
        return perform_instruction(bv, func, operands[0], depth)
    elif operation == MediumLevelILOperation.MLIL_SX:
        # TODO: Size Check?
        return perform_instruction(bv, func, operands[0], depth)
    elif operation == MediumLevelILOperation.MLIL_LOAD_SSA:
        # READ FROM MEMORY
        # TODO: Size
        r = Real("SomeMemory")
        dividends.append(r)
        return r
    else:
        print("Unknown operation {} ({})".format(repr(operation), repr(instruction)))
        # TODO: Check size w/ arch
        r = Real("Unknown Operation")
        dividends.append(r)
        return r

    return known_ssa_vars[ssa_instruction.dest]

def annotate_divisions_ssa(bv, addr, size):
    func = bv.get_functions_containing(addr)[0]
    instruction = func.get_low_level_il_at(addr).mlil.ssa_form
    result = perform_instruction(bv, func, instruction, 6)

    a = dividends[-1]
    print(simplify(result))
    s = Solver()
    s.add(a == 1)
    valid = s.check()
    if valid == sat:
        m = s.model()
        divisor = m.eval(1/result).as_decimal(4)
        if divisor[-1] == '?':
            divisor = divisor[:-1]
        print(round(float(divisor)))
    else:
        print("unsat")
