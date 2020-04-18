from .integer_division_binary_search import integer_division_binary_search
from .modulo_binary_search import modulo_binary_search
from .state import BacktrackingState
from .instructions import MLILInstructionExecutor
from z3 import Solver, simplify


def annotate_division_ending_at_address(bv, address):
    function = bv.get_functions_containing(address)[0]
    instruction = function.get_low_level_il_at(address).mlil.ssa_form
    backtracking_state = BacktrackingState(bv, function, depth=7)
    start = MLILInstructionExecutor(bv, instruction)
    start.execute(backtracking_state)

    input_bv = backtracking_state.potential_inputs[-1]
    output_bv = backtracking_state.variables[instruction.dest]

    def do_divide(dividend):
        s = Solver()
        s.set("timeout", 10)
        s.add(input_bv == dividend)
        s.check()
        m = s.model()
        solved = m.eval(output_bv)
        return solved.as_long()

    print(simplify(input_bv))
    print(simplify(output_bv))
    print(do_divide(10))
    print(do_divide(683958287))

    print(integer_division_binary_search(do_divide, 2 ** input_bv.size()))


def annotate_divisions_in_basic_block(bv, basic_block):
    pass


def annotate_divisions_in_function(bv, function):
    pass


def annotate_divisions_ssa(bv, addr, size):
    return annotate_division_ending_at_address(bv, addr)
