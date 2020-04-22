from .deoptimization import (
    annotate_division_ending_at_address,
    annotate_divisions_in_function,
)

from binaryninja.plugin import PluginCommand


PluginCommand.register_for_address(
    "Deoptimize Division - Line",
    "Uses smarts to deoptimize division",
    action=annotate_division_ending_at_address,
)

PluginCommand.register_for_function(
    "Deoptimize Division - Function",
    "Uses smarts to deoptimize division",
    action=annotate_divisions_in_function,
)
