# autoname_functions.py
#
# Make a backup of your IDB before you run this.  It will go through each string
# that has a single cross reference to a function, take the first one, then
# rename the function based on that string
#
# Weston Hopkins
# August 2014
#
from __future__ import division
from idaapi     import *
from idautils   import *
import re


# Change this higher if you want less names associated with each other.
# lower will give more false positives
PROBABILITY_CUTTOFF         = 0.5
STRING_PROBABILITY_CUTTOFF  = 0.10

UNNAMED_RE          = re.compile( r"^(sub|loc|flt|off|unk|byte|word|dword)_" )
AUTONAMED_RE        = re.compile( r"^z.?_" )


##############################################################################
# MarkovModel
##############################################################################
class MarkovModel:

    ##############################################################################
    def __init__(self, forStrings ):
        self.states     = {}
        self.xrefs      = {}
        self.forStrings = forStrings


    ##############################################################################
    def addTransition( self, fromStateID, toStateID ):
        
        if not fromStateID in self.states:
            newState = None
            if self.forStrings:
                newState = MarkovStateStrings(fromStateID, self)
            else:
                newState = MarkovStateCalls(fromStateID, self)
            self.states[fromStateID] = newState

        if not toStateID in self.xrefs:
            self.xrefs[toStateID] = 0

        self.xrefs[toStateID] += 1

        self.states[fromStateID].addTransition( toStateID )

    ##############################################################################
    def cull( self, cutoffWeight ):
        for sourceID in self.states:
            source = self.states[sourceID]
            edges = source.edges
            cullList = []
            for destID in edges:
                if source.probability(destID) < cutoffWeight:
                    cullList.append(destID)
            for destID in cullList:
                del source.edges[destID]

##############################################################################
# MarkovHashable
##############################################################################
class MarkovHashable:

    ##############################################################################
    def __init__(self, stateID, model):
        self.stateID    = stateID
        self.model      = model

    ##############################################################################
    def __hash__( self ):        
        return self.stateID

    ##############################################################################
    def __eq__(self, other ):
        return other.stateID == self.stateID

    ##############################################################################
    def __cmp__( self, other ):
        return self.stateID - other.stateID

    ##############################################################################
    def __repr__(self):
        return "%x" % self.stateID


##############################################################################
# MarkovState
##############################################################################
class MarkovState(MarkovHashable):

    def __init__(self, stateID, model):
        MarkovHashable.__init__(self, stateID, model)        

        self.transistions_total     = 0
        self.edges                  = {}
        self.model                  = model


    def addTransition( self, toStateID ):
        if not toStateID in self.edges:
            self.edges[toStateID] = 0

        self.edges[toStateID]   += 1
        self.transistions_total += 1

    def probabilityToString( self, toStateID ):
        return ": prob %0.3f = %d / %d" % (
            self.probability(toStateID),
            self.edges[toStateID],
            self.model.xrefs[toStateID]
            )

##############################################################################
# MarkovStateStrings
##############################################################################
class MarkovStateStrings(MarkovState):

    def __init__(self, stateID, model):
        MarkovState.__init__(self, stateID, model) 

    def probability( self, toStateID ):
        return self.edges[toStateID] / self.model.xrefs[toStateID]        


##############################################################################
# MarkovStateCalls
##############################################################################
class MarkovStateCalls(MarkovState):

    def __init__(self, stateID, model):
        MarkovState.__init__(self, stateID, model) 

    def probability( self, toStateID ):
        return self.edges[toStateID] /   self.transistions_total


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
        return name[2:]
    else:
        return name

##############################################################################
# safeName()
##############################################################################
def safeName( addr, baseName, msg="" ):

    oldName = Name(addr)
    # if oldName == baseName  or oldName.startswith(baseName):
    #     print( "!!! %s -> %s" % (oldName, baseName) )   

    newName = baseName
    Stats.renamesTotal += 1

    sc = MakeNameEx( addr, newName,  SN_NOCHECK | SN_AUTO | SN_NOWARN )
    i = 0
    while sc == 0:
        newName = baseName + str(i)
        sc = MakeNameEx( addr, newName,  SN_NOCHECK | SN_AUTO | SN_NOWARN )
        i += 1
        if i > 100000:
            errmsg = "Reached limit of autonaming.  Trying to create name %s which mean it went through %d iterations" % (newName, i)
            print errmsg
            raise errmsg

    
    print( "%s -> %s%s" % (oldName, newName, msg) )
    
##############################################################################
# Thing
##############################################################################
class Thing:

    #########################################################################
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

    #########################################################################
    # def xrefsFrom(self):
    #     xrefThings = set()
    #     map( lambda x: xrefThings.add(Thing(x)), self.xrefs_get() )
    #     return xrefThings

    #########################################################################
    def getXrefs(self):
        if self.xrefs:
            return self.xrefs
        
        self.xrefs = []
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
                    #self.xrefs.add(xrefFrom.to)
                    self.xrefs.append(xrefFrom.to)

        return self.xrefs


    #########################################################################
    def isNamed(self):
        return self.name and not UNNAMED_RE.match(self.name)

    #########################################################################
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
                        newName = "z_" + stripExistingPrefix(reffedThing.name)
                        #print( "%s -> %s" % ( thing, newName) )                        
                        safeName( thing.addr, newName  )
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
                    newName = "z_" + stripExistingPrefix(calledThing.name)
                    #print( "%s -> %s" % ( func, newName) )
                    changes += 1
                    safeName(func.addr, newName )
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
    if not s:
        return s
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

 
##############################################################################
# renameFunctionsBasedOnStrings()
##############################################################################
def renameFunctionsBasedOnStrings():
    print("Renaming functions based on strings...")
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
        oldThing = Thing(funcAddr)
        if( not oldThing.isNamed() ):
            newName = 'z_%s' % sanitizeString(string)
            safeName( funcAddr , newName ) 


##############################################################################
# fixupIdaStringNames()
##############################################################################
def fixupIdaStringNames():
    for s in Strings():
        name = Name(s.ea)
        if name and not name.startswith('z'):
            newName = "z%s" % sanitizeString(str(s))
            newName = newName[:256]
            safeName( s.ea, newName );

##############################################################################
# buildCallsModel()
##############################################################################
def runCallsModel():
    markovModel = MarkovModel(False)

    print("Building markov model for data...")
    for segment in Segments():
        seg = getseg(segment)
        clazz = get_segm_class(seg)
        if clazz == "CODE":
            continue
        for head in Heads( segment, SegEnd(segment) ):
            thing = Thing(head)
            if not thing.isFunction and thing.name and not thing.isNamed():
                for xref in thing.getXrefs():
                    markovModel.addTransition( thing.addr, xref )

    print("Building markov model for functions...")
    print("... chill mon.. this may take a while...")
    changes = 0
    allFunctionAddrs = Functions()
    for funcAddr in allFunctionAddrs:
        func = Thing(funcAddr)
        if not func.isNamed():
            for xref in func.getXrefs():
                markovModel.addTransition( func.addr, xref )

    print("Culling at %d %%" % (PROBABILITY_CUTTOFF*100) )
    markovModel.cull(PROBABILITY_CUTTOFF)

    changes = 1
    iteration = 0
    while changes > 0:
        print(" Pass %d" % iteration )
        changes = 0
        for sourceID in markovModel.states:
            sourceThing = Thing(sourceID)
            if sourceThing.isNamed():
                continue
            source = markovModel.states[sourceID]
            edges = sorted( source.edges, key=source.probability )
            for destID in edges:
                destThing = Thing(destID)
                if destThing.isNamed():
                    newName = "z_%s" % stripExistingPrefix( destThing.name )
                    #msg = ": probability = %0.3f" % source.probability(destID)
                    msg = ": " + source.probabilityToString(destID)
                    safeName( sourceThing.addr, newName, msg )
                    edge = source.edges[destID]
                    #print( "\t%f probability: %d / %d" % ( source.probability(destID), edge, source.transistions_total) ) 
                    changes += 1
                    break
        if iteration==0:
            renameFunctionsBasedOnStrings()
            changes += 1
        iteration += 1

        print("Pass %d, %d changes" % (iteration, changes) )
    return changes

##############################################################################
#
##############################################################################
def runStringsModel( filterEnabled ):
    validIdentifierRegex = re.compile( r"^[_a-zA-Z0-9]+$" )

    stringModel = MarkovModel(True)

    suffix = None
    if filterEnabled:
        suffix = "enabled"
    else:
        suffix = "disabled"

    print("Building markov model for strings with filter %s." % suffix)
    allStrings  = Strings(False)
    allStrings.setup( strtypes = Strings.STR_C )

    for index, stringItem in enumerate(allStrings):
        stringAddr = stringItem.ea
        string = str(stringItem)
        if not filterEnabled or validIdentifierRegex.match(string):
            for xref in XrefsTo(stringAddr, 0):
                functionAddr = xref.frm
                function = Thing(functionAddr)
                functionAddr = function.addr
                stringModel.addTransition( functionAddr, stringAddr )

    
    print("Culling at %d %%" % (STRING_PROBABILITY_CUTTOFF*100) )
    stringModel.cull(STRING_PROBABILITY_CUTTOFF)
    
    for sourceID in stringModel.states:
        sourceThing = Thing(sourceID)
        if sourceThing.isNamed():
            continue
        source = stringModel.states[sourceID]
        edges = sorted( source.edges, key=source.probability )
        for destID in edges:
            string = GetString(destID)
            if not string:
                continue
            string = sanitizeString(string)
            if  len(string)>4:
                newName = "z_%s" % string
                #msg = ": probability = %0.3f" % source.probability(destID)
                msg = ": %s" % ( source.probabilityToString(destID) )
                safeName( sourceThing.addr, newName, msg )
                edge = source.edges[destID]
                #print( "\t%f probability: %d / %d" % ( source.probability(destID), edge, source.transistions_total) ) 
                break


##############################################################################
# main()
##############################################################################
def main():

    fixupIdaStringNames()
    runStringsModel(True)
    runStringsModel(False)

    runCallsModel()

    print("DONE! %d changes total." % Stats.renamesTotal )


##############################################################################
# main_old()
##############################################################################
def main_old():

    fixupIdaStringNames()
    renameFunctionsBasedOnStrings()
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
    main()
    