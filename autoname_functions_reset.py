from __future__ import division
from idaapi     import *
from idautils   import *
import re



def main():
    print("Resetting names...")
    for segment in Segments():
        seg = getseg(segment)
        clazz = get_segm_class(seg)
        # We don't want to include functions since we'll do that in the next block
        for head in Heads( segment, SegEnd(segment) ):
            name = Name(head)
            if name and name.startswith("z_"):
                print(name)
                MakeName( head, "" )
    print("Done resetting names...")


main()
