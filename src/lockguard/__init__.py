"""lockguard - inspect npm dependency updates for malicious-looking code before you merge them.

The public entry points are the ``lockguard`` command line tool (:mod:`lockguard.cli`) and
the analysis engine (:func:`lockguard.engine.analyze_changes`).
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
