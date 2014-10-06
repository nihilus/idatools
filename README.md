idatools
========

Tools for IDA


xref_trees.py
-------------

Builds up a callgraph of cross references to and from a function and spits it out as a text...




autorename_functions.py
-----------------------

Finds unique strings references by a function and renames the function based on
the string.  This is useful if you have functions that log, but don't have symbols.  It will
take the strings references in the log calls and rename your functions.  I need some better heuristics
in the future for this...