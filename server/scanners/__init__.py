"""Contains scanner modules."""
import os

temporary_all = []
for scanner in os.listdir(os.path.dirname(__file__)):
    if scanner != "__init__.py":
        temporary_all.append(scanner.replace(".py", ""))

__all__ = temporary_all
