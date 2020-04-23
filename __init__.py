from .deoptimization import (
    annotate_operations_ending_at_address,
    annotate_operations_in_function,
)

from binaryninja.plugin import PluginCommand


PluginCommand.register_for_address(
    "Deoptimize Operations - Line",
    "Uses z3 to deoptimize divisions and modulos ending at the specified line.",
    action=annotate_operations_ending_at_address,
)

PluginCommand.register_for_function(
    "Deoptimize Operations - Function",
    "Uses z3 to deoptimize divisions and modulos through the current function.",
    action=annotate_operations_in_function,
)
