idatools
========

Tools for IDA



autorename_functions.py
-----------------------

**Backup your IDB first** 

Will name your functions and data based on strings and other symbols using a Markov model.    All names are prefixed with ***'z_'*** .  Only symbols that
aren't already named will be changed.  For example for functions, only names that starts with ***'sub_'*** will change.

First step, it renames all the strings to something sane.  I'm not a fan of IDA's aCamelCaseNaming of strings.  Unlike IDA, 
this won't truncate a string until 256 bytes and spaces are replaced with '_' instead of an empty string.

Second, it finds unique strings references by a function and renames the function based on
the string.  This is useful if you have functions that log, but don't have symbols.  It will
take the strings references in the log calls and rename your functions.  I need some better heuristics
in the future for this.  String based functions are prefixed with 'z_'

###Markov Model
It then builds a Markov model of the cross reference graph between data and code.  The number of cross references over the total number of outgoing edges is used to
approximate the probability of the model.  This weights which names to generate.  An arbitrary cutoff of 0.5 was picked, but you can adjust 
this by changing ***PROBABILITY_CUTTOFF*** at the top of the file.  Any named Xref that is >= the cutoff is used as the name of the symbol. 

Once the model is built, it will continue through passes of data and code, renaming as it goes, until there is nothing left to rename.
  

xref_trees.py
-------------

Builds up a callgraph of cross references to and from a function and spits it out as a text...



