# autoname_functions.py
#
# Make a backup of your IDB before you run this.  It will go through each string
# that has a single cross reference to a function, take the first one, then
# rename the function based on that string
#
# Weston Hopkins
# August 2014
#

from idaapi     import *
from idautils   import *
import re


BADPREFIXES_RE  = re.compile( r"^(sub|loc|flt|off|unk|byte|word|dword)_" )
AUTONAMED_RE    = re.compile( r"^z.?_" )


##############################################################################
# Stats
##############################################################################
class Stats:
    renamesTotal        = 0


##############################################################################
# stripExistingPrefix()
##############################################################################
def stripExistingPrefix( name ):
    if AUTONAMED_RE.match(name):
        return name[3:]
    else:
        return name

##############################################################################
# safeName()
##############################################################################
def safeName( addr, baseName, oldName ):

    if oldName == baseName:
        return

    newName = baseName
    Stats.renamesTotal += 1

    for suffix in [""] +  [ str(x) for x in range(10000)]:        
        newName = baseName + str(suffix)
        ret = MakeNameEx( addr, newName,  SN_NOCHECK | SN_AUTO | SN_NOWARN )
        if ret != 0:
            print( "%s -> %s" % ( oldName, newName) )
            return

    errorMessage =  "Unable to name variable: %s -> %s @ %s" % (oldName, baseName, newName)
    print( errorMessage )
    raise( errorMessage )
    
##############################################################################
# Thing
##############################################################################
class Thing:

    def __init__( self, addr ):
        self.isFunction         = None
        self.xrefs              = None
        self.endEA              = None

        funcAddr = get_func(addr)
        if funcAddr:
            self.addr       = funcAddr.startEA
            self.endEA      = funcAddr.endEA
            self.isFunction = True
        else:
            self.addr       = addr
            self.endEA      = addr + 4 
            self.isFunction = False        

        self.name = Name(self.addr)
        testName = Demangle( self.name, INF_LONG_DN)
        if testName:
            self.name = testName

    # def _xrefsTo(self):
    #     xrefs = set()
    #     i=0
    #     for xref in XrefsTo( self.addr, 0 ) :
    #         xrefs.add(Thing(xref.frm))
    #         i += 1
    #         if i > 2:
    #             return xrefs
    #     return xrefs


    def xrefsFrom(self):
        xrefThings = set()
        map( lambda x: xrefThings.add(Thing(x)), self.xrefs_get() )
        return xrefThings

    def xrefs_get(self):
        if self.xrefs:
            return self.xrefs
        self.xrefs = set()        
        if self.isFunction:
            fromAddrs = FuncItems( self.addr )
        else:
            fromAddrs = [self.addr]


        for fromAddr in fromAddrs:
            for xrefFrom in XrefsFrom( fromAddr, 0 ):
                # Make sure it's not self referential
                # this does sometimes result in false positives because of the end
                # condition, but you can see why that might be beneficial most of the
                # time
                if xrefFrom.to < self.addr or xrefFrom.to > self.endEA: 
                    self.xrefs.add(xrefFrom.to)
                    if len(self.xrefs) > 1:
                        return self.xrefs

        return self.xrefs



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


##############################################################################
# renameData()
##############################################################################
def renameData():
    print("Renaming Data...")
    changes = 0
    for segment in Segments():
        seg = getseg(segment)
        clazz = get_segm_class(seg)
        if clazz == "CODE":
            continue
        for head in Heads( segment, SegEnd(segment) ):
            thing = Thing(head)
            if not thing.isFunction and thing.name and not thing.isNamed():
                xrefs_from = thing.xrefsFrom()
                if len(xrefs_from) == 1:
                    reffedThing = xrefs_from.pop()
                    if( reffedThing.isNamed() ):
                        newName = "zd_" + stripExistingPrefix(reffedThing.name)
                        #print( "%s -> %s" % ( thing, newName) )                        
                        safeName( thing.addr, newName, thing.name  )
                        changes += 1
    return changes

##############################################################################
# renameFunctions()
##############################################################################
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
                    newName = "zf_" + stripExistingPrefix(calledThing.name)
                    #print( "%s -> %s" % ( func, newName) )
                    changes += 1
                    safeName(func.addr, newName, func.name )
    return changes


            # if( len(xrefs_from) == 1) :
            #     func_from = xrefs_from.pop()
            #     func_from = Thing(func_from)
            #     if( func_from.isNamed() ):
            #         print( "%s -> %s" % (func_from, func) )          

    
##############################################################################
# xrefToString()
##############################################################################
def xrefToString(xref):
    return "%s -> %s : %s" % ( hex(xref.frm), hex(xref.to), XrefTypeName(xref.type))

##############################################################################
# sanitizeString()
##############################################################################
def sanitizeString(s):
    ret = s
    ret =  re.sub( r'%[\+ -#0]*[\d\.]*[lhLzjt]{0,2}[diufFeEgGxXoscpaAn]', '_', ret  )
    ret =  re.sub( r'[^a-zA-Z0-9_]+', '_', ret )
    ret =  re.sub( r'_+', '_', ret )
    return ret.strip('_')

##############################################################################
# processStringXrefs()
##############################################################################
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

 
##############################################################################
# renameStrings()
##############################################################################
def renameStrings():
    print("Renaming based on strings...")
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
        safeName( funcAddr , newName, oldName ) 

##############################################################################
# fixupIdaStringNames()
##############################################################################
def fixupIdaStringNames():
    for s in Strings():
        name = Name(s.ea)
        if name and name.startswith('a'):
            newName = "z%s" % sanitizeString(str(s))
            newName = newName[:128]
            safeName( s.ea, newName, name );


##############################################################################
# main()
##############################################################################
def main():

    fixupIdaStringNames()
    renameStrings()
    changes = 1
    iteration = 0
    while changes > 0:
        iteration += 1
        changes = 0
        print( "Pass %d." % iteration )
        changes += renameData()
        print( "Pass %d." % iteration )
        changes += renameFunctions()
        print( "Pass %d had %d changes" % (iteration, changes ) )
    

    print("Done with a total of %d changes" % Stats.renamesTotal )

if __name__ == '__main__':
    #tester()
    main()
