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

from 	idaapi import *
from 	idautils import *
import 	json
import 	sys
import 	SimpleHTTPServer
import 	BaseHTTPServer
import 	SocketServer
import 	os.path
import 	webbrowser

functionAddresses = {}


BLACKLIST = ['alloc', 'zzz_']


def demangledName(addr):
    name = Name(addr)
    testName = Demangle( name, INF_LONG_DN)
    if testName:
        name = testName
    return name

######################################################################
######################################################################
class XTree(dict):

	def __init__(self, name, addr):
		self["name"] 		= name
		self["children"] 	= []
		self["addr"] 	 	= addr
		self["size"] 		= 0


	def add(self, kidTree):
		self["children"].append(kidTree)
		self["size"] += 1


######################################################################
# XTreeServer
######################################################################
class XTreeServer(SimpleHTTPServer.SimpleHTTPRequestHandler):

	def do_GET(self):
		if self.path == "/xtree.json":
			self.send_response(200)
			self.send_header('Content-type', 'application/javascript')
			self.end_headers()
			self.wfile.write(self.server.xtree_json)
			self.server.finished = True
		else:
			return SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)




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
def dumpXrefsFrom( pc, callStack, functionCallCounts, parentTree ):
	func = get_func(pc)

	if func is None:
		print( "0x%08x is not at a function\n" % pc )
		return

	func = get_func(func.startEA)
	dumpShit(func)
	functionName = demangledName(func.startEA)

	for blackList in BLACKLIST:
		if( blackList in functionName ):
			return
	if( functionName in callStack ):
		return
	else:
		callStack.append(functionName)

	if( not functionName in  functionCallCounts ):
		functionCallCounts[functionName] = 0

	functionCallCounts[functionName] = functionCallCounts[functionName] + 1
	functionCallCount = functionCallCounts[functionName]
	tree = XTree( functionName, func.startEA )
	parentTree.add(tree)

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
						dumpXrefsFrom( xref.to, list(callStack), functionCallCounts, tree )
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
	functionName = demangledName(func.startEA)
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
	functionName = demangledName(func.startEA)
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


def startServer(tree):
	
	homedir = os.path.dirname( sys.argv[0] )
	os.chdir(homedir)
	print("Starting server in %s" % homedir )
	print(" go to: http://localhost:6969")
	webbrowser.open("http://localhost:6969" )
	httpd = BaseHTTPServer.HTTPServer( ("127.0.0.1", 6969), XTreeServer )
	httpd.finished = False
	httpd.xtree_json = json.dumps(tree)
	while not httpd.finished:
		try:
			httpd.handle_request()
		except KeyboardInterrupt:
			httpd.finished = True
	httpd.server_close()
	print("Done")

def main():

	print sys.argv

	functionEA = ChooseFunction("Select function to generate graph")
	if BADADDR == functionEA:
		print("No function selected. exiting... ")
		return

	Message( "=" * 80 + "\n" )
	Message("Cross References From\n")
	Message( "=" * 80 + "\n" )
	name = demangledName(functionEA)
	tree = XTree(name, functionEA)
	dumpXrefsFrom(functionEA, [], {}, tree )

	startServer(tree)	


	# filename = "xtree.json"
	# Message("Writing tree to %s.\n" % filename)
	# f = file(filename, "w+")	
	# f.write(json.dumps(tree))
	# f.close()


main()

# Message( "=" * 80 + "\n" )
# Message("Cross References To\n")
# Message( "=" * 80 + "\n" )
# dumpXrefsTo(functionEA, [], {} )
