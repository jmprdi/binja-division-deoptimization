from .deoptimization import annotate_divisions

from binaryninja.plugin import PluginCommand

PluginCommand.register_for_function(
    "Deoptimize Division - Func",
    "Uses smarts to deoptimize division",
    action=annotate_divisions,
)
