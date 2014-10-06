# autoname_functions.py
#
# Make a backup of your IDB before you run this.  It will go through each string
# that has a single cross reference to a function, take the first one, then
# rename the function based on that string
#
# Weston Hopkins
# August 2014
#

from idaapi import *
from idautils import *
import re


def xrefToString(xref):
    return "%s -> %s : %s" % ( hex(xref.frm), hex(xref.to), XrefTypeName(xref.type))


def sanitizeString(s):
    ret =  re.sub( r'[^a-zA-Z0-9_]+', '_', s )
    return ret.strip('_')

def processStringXrefs(item, functionsHash):
    links = [] 
    string = str(item)
    string = string.strip()

    for xref in XrefsTo(item.ea, 0):
        refAddr = xref.frm
        func = get_func(refAddr)
        if func:
            funcAddr = func.startEA
            functionName = Name(funcAddr)

            if( functionName.startswith( 'sub_' ) or functionName.startswith('z_') ):
                link = (funcAddr, refAddr, string )
                links.append(link)


    if( len(links) == 1 ):
        link        = links[0]
        funcAddr    = link[0]
        lastLink    = link
        try:
            lastLink = functionsHash[funcAddr]
        except:
            functionsHash[funcAddr] = link

        if( link[1] < lastLink[1] ):
            functionsHash[funcAddr] = link

 

def main():
    allStrings = Strings(False)
    allStrings.setup( strtypes = Strings.STR_C )
    # key : function EA
    # value : ( Xref, string )

    functionsHash = {}

    for index, stringItem in enumerate(allStrings) :
        if stringItem is None :
            print("Nothing for string #%d" % index )
        else:
            processStringXrefs( stringItem, functionsHash )

    for funcAddr in functionsHash.keys() :
        link    = functionsHash[funcAddr]
        refAddr = link[1]
        string  = link[2]
        oldName = Name(funcAddr)
        newName = 'z_%s' % sanitizeString(string)
        print( "%s() -> %s" % ( oldName, newName ) )
        MakeNameEx( funcAddr , newName, SN_NOWARN) 

    print("Done!")



main()