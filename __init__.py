
import os
import sys


try:
    _base_dir = os.path.dirname(os.path.abspath(__file__))
    _vendor_dir = os.path.join(_base_dir, 'vendor')

    if os.path.exists(_vendor_dir) and _vendor_dir not in sys.path:
        sys.path.insert(0, _vendor_dir)
except NameError:
    pass

__version__ = "1.0.0"
__author__ = "Guy Voloshin"