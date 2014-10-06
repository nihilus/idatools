# callgraph_tree.py
#
# This generates a call graph in a tree format.  It will ignore allocs and any
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
		if( functionName.__contains__(blackList) ):
			return
	if( callStack.__contains__(functionName) ):
		return
	else:
		callStack.append(functionName)

	if( not functionCallCounts.__contains__(functionName) ):
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
					if( not xrefs.__contains__(xrefName) ):
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
		if( functionName.__contains__(blackList) ):
			return
	if( callStack.__contains__(functionName) ):
		return
	else:
		callStack.append(functionName)

	if( not functionCallCounts.__contains__(functionName) ):
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
				if( not xrefs.__contains__(xrefName) ):
					dumpXrefsTo( xref.frm, list(callStack), functionCallCounts )
					xrefs.append(xrefName)


Message( "=" * 80 + "\n" )
Message("Cross References From\n")
Message( "=" * 80 + "\n" )
dumpXrefsFrom(here(), [], {} )

Message( "=" * 80 + "\n" )
Message("Cross References To\n")
Message( "=" * 80 + "\n" )
dumpXrefsTo(here(), [], {} )
