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


BADPREFIXES_RE = re.compile( r"^(sub|loc|flt|off|unk|byte|word|dword)_" )
AUTONAMED_RE   = re.compile( r"^z.?_" )


def safeName( addr, baseName ):

    newName = baseName
    
    for suffix in [""] +  [ str(x) for x in range(1000)]:        
        newName = baseName + str(suffix)
        ret = MakeNameEx( addr, newName,  SN_NOCHECK | SN_AUTO | SN_NOWARN )
        if ret != 0:
            return
    

class Thing:
    def __init__( self, addr ):
        
        funcAddr = get_func(addr)
        if funcAddr:
            self.addr = funcAddr.startEA
            self.isFunction = True
        else:
            self.addr = addr
            self.isFunction = False        

        self.name = Name(self.addr)
        testName = Demangle( self.name, INF_LONG_DN)
        if testName:
            self.name = testName

        #self.name = get_name(self.addr)

    def xrefsTo(self):
        xrefs = set()
        map( lambda x: xrefs.add(Thing(x.frm)), XrefsTo( self.addr, 0 ) )
        # for xref in XrefsTo( self.addr, 0 ):
        #     thingTest = Thing(xref.frm)
        #     if( thingTest.isNamed() ):
        #         xrefs.add(xref.frm)
        return xrefs

    def xrefsFrom(self):
        xrefs = set()
        
        if self.isFunction:
            fromAddrs = FuncItems( self.addr )
        else:
            fromAddrs = [self.addr]

        for fromAddr in fromAddrs:
            for xrefFrom in XrefsFrom( fromAddr, 0 ):
                xrefThing = Thing(xrefFrom.to)
                if xrefThing.addr != self.addr:
                    xrefs.add(xrefThing)

            #map( lambda x: xrefs.add(x.to),  XrefsFrom( fromAddr, 0 ) )        

        return xrefs

    def isNamed(self):
        return self.name and not BADPREFIXES_RE.match(self.name)


    def suffix(self):
        if self.isFunction:
            return "()"
        else:
            return "@"

    def __repr__(self):
        return "%s%s" % (self.name, self.suffix())


    def __hash__(self):
        return self.addr

    def __eq__(self, other):
        return self.addr == other.addr

    def __cmp__(self, other):
        return  self.addr - other.addr



def renameData():
    print("Renaming Data...")
    changes = 0
    for segment in Segments():
        for head in Heads( segment, SegEnd(segment) ):
            thing = Thing(head)
            if not thing.isFunction and thing.name and not thing.isNamed():
                xrefs_from = thing.xrefsFrom()
                if len(xrefs_from) == 1:
                    reffedThing = xrefs_from.pop()
                    if( reffedThing.isNamed() ):
                        newName = "zd_" + reffedThing.name
                        print( "%s -> %s" % ( thing, newName) )
                        safeName(thing.addr, newName )
                        changes += 1
    return changes

def renameFunctions():
    print("Renaming Functions...")
    changes = 0
    allFunctionAddrs = Functions()
    for funcAddr in allFunctionAddrs:
        func = Thing(funcAddr)
        if not func.isNamed():
            #xrefs_to = func.xrefsTo()
            xrefs_from = func.xrefsFrom()
            if len(xrefs_from) == 1:
                calledThing = xrefs_from.pop()
                if( calledThing.isNamed() ):
                    newName = "zf_" + calledThing.name
                    print( "%s -> %s" % ( func, newName) )
                    changes += 1
                    safeName(func.addr, newName )
    return changes


            # if( len(xrefs_from) == 1) :
            #     func_from = xrefs_from.pop()
            #     func_from = Thing(func_from)
            #     if( func_from.isNamed() ):
            #         print( "%s -> %s" % (func_from, func) )          

    

def xrefToString(xref):
    return "%s -> %s : %s" % ( hex(xref.frm), hex(xref.to), XrefTypeName(xref.type))


def sanitizeString(s):
    ret = s
    ret =  re.sub( r'%[\+ -#0]*[\d\.]*[lhLzjt]{0,2}[diufFeEgGxXoscpaAn]', '_', ret  )
    ret =  re.sub( r'[^a-zA-Z0-9_]+', '_', ret )
    ret =  re.sub( r'_+', '_', ret )
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

            if( functionName.startswith( 'sub_' ) or functionName.startswith('zs_') ):
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

 

def renameStrings():
    print("Renaming strings...")
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
        newName = 'zs_%s' % sanitizeString(string)
        if oldName != newName:
            print( "%s() -> %s" % ( oldName, newName ) )
            safeName( funcAddr , newName ) 
    
def fixupIdaStringNames():
    for s in Strings():
        name = Name(s.ea)
        if name and name.startswith('a'):
            newName = "a_%s" % sanitizeString(str(s))
            newName = newName[:128]
            print("%s -> %s" % (name, newName) )
            safeName( s.ea, newName );


def tester():
    addr = 0x808EFA38
    thing = Thing(addr)
    froms = thing.xrefsFrom()
    tos = thing.xrefsTo()
    print("%d -> %d" % ( len(tos), len(froms) ) )
    for f in froms:
        print("%s - %x" % (f, f.addr) )
def main():

    fixupIdaStringNames()
    renameStrings()
    changes = 1
    iteration = 0
    while changes > 0:
        iteration += 1
        changes = 0
        print( "Iteration %d." % iteration )
        changes += renameData()
        print( "Iteration %d." % iteration )
        changes += renameFunctions()
        print( "Iteration %d had %d changes" % (iteration, changes ) )
    

    print("Done!")

if __name__ == '__main__':
    tester()
    #main()
