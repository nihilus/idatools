idatools
========

Tools for IDA



autorename_functions.py
-----------------------

**Backup your IDB first** 

This will attempt to name your functions based on strings and relationships between other functions and data in your idb.

First step, it finds unique strings references by a function and renames the function based on
the string.  This is useful if you have functions that log, but don't have symbols.  It will
take the strings references in the log calls and rename your functions.  I need some better heuristics
in the future for this.  String based functions are prefixed with 'zs_'

The second step finds all data that has only one, named outgoing reference, and creates a name based on that.  This data is prefixed with ***'zd_'*** .

The last step enumerates all the unnamed functions and looks for outgoing references as well, and names the functions with a ***'zf_'*** prefix.

It will continue through passes of the  2nd and 3rd steps until they are no further changes.
  
TODO: Speed it up

xref_trees.py
-------------

Builds up a callgraph of cross references to and from a function and spits it out as a text...



