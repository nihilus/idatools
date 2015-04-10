#
# this will attempt to create functions that were missed by IDA
#
from idaapi     import *
from idautils   import *

def main():
    
    totalCreations = 0
    prologMneumonics = ["PUSH", "STM"]  # , "LDRB", "LDR"]
    epilogMneumonics = ["POP", "LDM"]
    for segment in Segments():
        seg = getseg(segment)
        clazz = get_segm_class(seg)
        if clazz != "CODE":
            continue
        startAddr   = BADADDR
        endAddr     = BADADDR
        for head in Heads( segment, SegEnd(segment) ):
            if GetFunctionFlags(head) == -1:
                mneumonic = GetMnem(head)
                operand = GetOpnd( head, 0 )
                if startAddr==BADADDR and mneumonic in prologMneumonics:
                    if "LR" in operand:
                        assembler = GetDisasm(head)
                        print( "Start %x: %s" % (head, assembler) )
                        startAddr = head
                        endAddr = BADADDR
                if startAddr!=BADADDR and mneumonic in epilogMneumonics:
                    if "PC" in operand:
                        assembler = GetDisasm(head)
                        print( "End   %x: %s" % (head, assembler) )
                        endAddr = head

            if startAddr!=BADADDR and endAddr!=BADADDR:
                MakeFunction( startAddr, endAddr )
                newName = Name(startAddr)
                print( "Created %s : 0x%x ... 0x%x" % (newName, startAddr, endAddr) )
                totalCreations += 1
                startAddr   = BADADDR
                endAddr     = BADADDR
    print("Done.  Created %d functions" % totalCreations )


main()