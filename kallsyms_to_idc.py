import re
import os
import sys


def usage():
    print("%s <path to kallsyms>" % sys.argv[0] )
    print("%s /proc/kallsyms" % sys.argv[0] )


def main():
    prefix = """
#define UNLOADED_FILE   1
#include <idc.idc>

static main(void)
{
    """

    suffix = '}'
    format = '\tMakeName\t (0x%s, "%s");'

    regex = re.compile( r'([a-fA-Z0-9]+) \w (\w+)' )


    if( len(sys.argv) != 2 ):
        return usage()

    kallsymsPath = sys.argv[1]

    f = open( kallsymsPath, "r" )
    if None == f:
        print("Unable to open %s.\n", kallsymsPath )
        return -3


    print( "// Enabling addresses...")
    cmd = 'echo 1 > /proc/sys/kernel/kptr_restrict'
    os.system( cmd )
    
    print(prefix)
    lines = f.readlines()
    for line in lines:
        match = regex.match(line)
        if( match != None ):
            print( format % (match.group(1), match.group(2)) )

    f.close()

    print(suffix)
    return 0
  
if __name__ == '__main__':
    main()
 