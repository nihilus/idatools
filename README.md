idatools
========

Tools for IDA



autorename_functions.py
-----------------------

**Backup your IDB first** 

This will, iteratively, attempt to name your functions based on strings and relationships between other functions and data in your idb.

First pass, it finds unique strings references by a function and renames the function based on
the string.  This is useful if you have functions that log, but don't have symbols.  It will
take the strings references in the log calls and rename your functions.  I need some better heuristics
in the future for this.  String based functions are prefixed with 'zs_'

Second pass finds all data that has only 





xref_trees.py
-------------

Builds up a callgraph of cross references to and from a function and spits it out as a text...



