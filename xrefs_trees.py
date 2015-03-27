# xref_trees.py
#
# This generates callgraph trees to and from the current function.  
# It will ignore allocs and any
# functions that start with zzz_ .  You can add other functions you want to 
# ignore in BLACKLIST
#
# Weston Hopkins 
# August 2014
#

from idaapi import *
from idautils import *

functionAddresses = {}


BLACKLIST = ['alloc', 'zzz_']

######################################################################
# dumpShit()
######################################################################
def dumpShit(obj, name=""):
	return
	Message( "%s: %s\n" % (name, obj )) 
	for attr in dir(obj):
		val = None
		try:
			val = eval( "obj." + attr )
		except:
			pass
		Message( "\t%s: \t%s\n" % (attr, val))


######################################################################
# dumpXrefsFrom()
######################################################################
def dumpXrefsFrom( pc, callStack, functionCallCounts ):
	func = get_func(pc)

	if func is None:
		# print( "0x%08x is not at a function\n" % pc )
		return

	func = get_func(func.startEA)
	dumpShit(func)
	functionName = Name(func.startEA)
	if( functionName[0] == '_' ):
		return
	for blackList in BLACKLIST:
		if( blackList in functionName ):
			return
	if( functionName in callStack ):
		return
	else:
		callStack.append(functionName)

	if( not functionName in functionCallCounts ):
		functionCallCounts[functionName] = 0

	functionCallCounts[functionName] = functionCallCounts[functionName] + 1
	functionCallCount = functionCallCounts[functionName]

	prefix = "   |" * len(callStack)
	Message( prefix[:-1] + "+ " + functionName + "()" )

	if( functionCallCount>1 ):
		Message(" ... [%d]\n" % functionCallCount )
	else:
		Message("\n")
		functionCallCounts[functionName] = True
		items = FuncItems( func.startEA )
		xrefs = []
		for i in items:
			for xref in XrefsFrom(i, 0):
				if xref.type==fl_CN or xref.type==fl_CF or xref.type==fl_JF or xref.type==fl_JN:
					xrefName = str(xref.to)
					if( not xrefName in xrefs ):
						dumpXrefsFrom( xref.to, list(callStack), functionCallCounts )
						xrefs.append(xrefName)


######################################################################
# dumpXrefsFrom()
######################################################################
def generateCallsJSONTree( pc, callStack, functionCallCounts ):
	func = get_func(pc)

	if func is None:
		# print( "0x%08x is not at a function\n" % pc )
		return

	func = get_func(func.startEA)
	dumpShit(func)
	functionName = Name(func.startEA)
	if( functionName[0] == '_' ):
		return
	for blackList in BLACKLIST:
		if( blackList in functionName ):
			return
	if( functionName in callStack ):
		return
	else:
		callStack.append(functionName)

	if( not functionName in functionCallCounts ):
		functionCallCounts[functionName] = 0

	functionCallCounts[functionName] = functionCallCounts[functionName] + 1
	functionCallCount = functionCallCounts[functionName]

	prefix = "   |" * len(callStack)
	Message( prefix[:-1] + "+ " + functionName + "()" )

	if( functionCallCount>1 ):
		Message(" ... [%d]\n" % functionCallCount )
	else:
		Message("\n")
		functionCallCounts[functionName] = True
		items = FuncItems( func.startEA )
		xrefs = []
		for i in items:
			for xref in XrefsFrom(i, 0):
				if xref.type==fl_CN or xref.type==fl_CF or xref.type==fl_JF or xref.type==fl_JN:
					xrefName = str(xref.to)
					if( not xrefName in xrefs ):
						dumpXrefsFrom( xref.to, list(callStack), functionCallCounts )
						xrefs.append(xrefName)



######################################################################
# dumpXrefsTo()
######################################################################
def dumpXrefsTo( pc, callStack, functionCallCounts ):
	func = get_func(pc)

	if func is None:
		# print( "0x%08x is not at a function\n" % pc )
		return

	func = get_func(func.startEA)
	dumpShit(func)
	functionName = Name(func.startEA)
	if( functionName[0] == '_' ):
		return
	for blackList in BLACKLIST:
		if( blackList in functionName ):
			return
	if( functionName in callStack ):
		return
	else:
		callStack.append(functionName)

	if( not functionName in functionCallCounts ):
		functionCallCounts[functionName] = 0

	functionCallCounts[functionName] = functionCallCounts[functionName] + 1
	functionCallCount = functionCallCounts[functionName]

	prefix = "   |" * len(callStack)
	Message( prefix[:-1] + "+ " + functionName + "()" )

	if( functionCallCount>1 ):
		Message(" ... [%d]\n" % functionCallCount )
	else:
		Message("\n")
		functionCallCounts[functionName] = True
		xrefs = []

		for xref in XrefsTo(func.startEA, 0 ):
			if xref.type==fl_CN or xref.type==fl_CF or xref.type==fl_JF or xref.type==fl_JN:
				xrefName = str(xref.frm)
				if( not xrefName in xrefs ):
					dumpXrefsTo( xref.frm, list(callStack), functionCallCounts )
					xrefs.append(xrefName)

functionEA = ChooseFunction("Select function to generate graph")

Message( "=" * 80 + "\n" )
Message("Cross References From\n")
Message( "=" * 80 + "\n" )
dumpXrefsFrom(functionEA, [], {} )

Message( "=" * 80 + "\n" )
Message("Cross References To\n")
Message( "=" * 80 + "\n" )
dumpXrefsTo(functionEA, [], {} )
