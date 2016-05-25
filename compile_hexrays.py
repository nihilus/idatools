import re
import sys

UNDECLARED_IDENTITIER_REGEX     = re.compile(r".*error: use of undeclared identifier '([^']+)'")
REFERENCED_FUNCTION_REGEX       = re.compile( r'.*"([^"]+)", referenced from:.*')


def usage():
    print("compile_hexrays.py <preprocess | header>")


def preprocess(f):

    currentlySkipping       = False
    openCurlies             = 0
    closeCurlies            = 0

    for line in f.readlines():
        line = line.rstrip()
        line = line.replace( "::", "__" )

        if '#error' in line:
            continue

        if '#include <defs.h>' in line:
            print('#include "defs.h"')
            print('#include "hexrays_kludge.h"')
            continue

        if '__asm' in line:
            currentlySkipping   = True
            openCurlies         = 0
            closeCurlies        = 0
        
        if currentlySkipping:
            openCurlies     += line.count('{')
            closeCurlies    += line.count('}')            
            if openCurlies>0 and openCurlies-closeCurlies == 0:
                currentlySkipping = False
            continue

        print(line)


        
def main():


    if len(sys.argv) != 2:
        usage()
        return

    f = sys.stdin
    if( "preprocess" in sys.argv[1] ):
        preprocess(f)
    elif( "header"  in sys.argv[1] ):
        generateHeader(f)
    else:
        usage()


def generateHeader(f):
    undeclaredIdentifiers = set()
    referencedFunctions = set()

    for line in f.readlines():
        line = line.strip()
        match = UNDECLARED_IDENTITIER_REGEX.match(line)
        if match:
            undeclaredIdentifiers.add(match.group(1))

        match = REFERENCED_FUNCTION_REGEX.match(line)
        if match:
            referencedFunctions.add(match.group(1))

    for undec in undeclaredIdentifiers:
        print( "int %s;" % undec );

    for func in referencedFunctions:
        print( "int %s(int x, ...) {return 0;}" % func[1:] )


if __name__ == "__main__":
    main()