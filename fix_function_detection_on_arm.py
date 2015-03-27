#
# this will attempt to create functions that were missed by IDA
#
from idaapi     import *
from idautils   import *

def main():
    
    for segment in Segments():
        seg = getseg(segment)
        clazz = get_segm_class(seg)
        if clazz != "CODE":
            continue
        for head in Heads( segment, SegEnd(segment) ):
            if GetFunctionFlags(head) == -1:
                opcode = GetMnem(head)
                manual = GetManualInsn(head)
                if opcode == "PUSH" or opcode == "STMFD" or opcode=="LDRB" or opcode=="LDR":
                    print( "%x %s - %s" % (head,opcode,manual) )
                    MakeFunction( head, BADADDR )


main()