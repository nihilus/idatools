from __future__ import division
from idaapi     import *
from idautils   import *
import re


def main():
    allFunctionAddrs = Functions()
    for funcAddr in allFunctionAddrs:
        name = Name(funcAddr)
        if name and name.startswith("z_"):
            print(name)
            MakeName(funcAddr, "" )

main()