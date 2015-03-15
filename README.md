# AclCheck

*AclCheck* is a simple console application written in C++ for complete static analysis of Access Control Lists contained in a network device configuration. Tool detects conflicts among rules of each ACL in a given configuration file. Used analysis algorithm is fast enough even for very large ACLs (10000+ rules).

## Details

Tool implements and uses:
 * Algorithm for classification of conflict between pair of ACL rules based on [research by Al-Shaer](http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=1354680&isnumber=29753).
 * Conflict terminology proposed and used by [Al-Shaer](http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=1354680&isnumber=29753).
 * Algorithm using tries, based on [research by Barboescu an Varghese](http://www.cs.ucsd.edu/~varghese/PAPERS/compnetworks2003.pdf), used for reducing number of analysed ACL rule pairs.
 * Focused only on IPv4 ACL rules.

## Tool background
*AclCheck* was created as part of a [master thesis](http://www.fit.vutbr.cz/study/DP/DP.php.en?id=14141&y=2011) (thesis is written in Slovak language) on Faculty of Information Technology of the Brno University of Technology in Czech Republic in 2012. Work has been also presented on EEICT 2012 conference. Paper from the conference is [here](http://www.feec.vutbr.cz/EEICT/2012/sbornik/02magisterskeprojekty/08informacnisystemy/03-xhozza00.pdf) (in English).

### Thesis abstract
Some problems in configurations of network devices are difficult to identify. Access control lists present an important part of many configurations. Conflicts among rules of an access control list can cause holes in security policy or quality of service. In this paper we focus on identifying and classifying conflicts among rules of an access control list. Discovering all possible types of conflicts is not a trivial task. We present optimized algorithm for complete access control list analysis using tries, based on existing research by Baboescu and Varghese. The tool for detecting conflicts among access control list rules of one given Cisco, HP or Juniper device using tries based algorithm has been implemented. Bit vectors in tries use compression to reduce memory consumption. Implemented tool was tested for correctness and performance. The hypothesis that this solution would make the analysis of access lists significantly faster has been proven.

### Further development
There is not any ongoing development or improvement of the tool. Tool is finished, stable, tested and usable. Although **any patches or features implementations, that doesn't break already implemented features are very welcome**. Everybody is free to use, copy and modify the source code with compliance with GNU/GPLv3 license.


## Implementation
  * C++ language
  * [standard C++ library](http://gcc.gnu.org/libstdc++/)
  * [RapidXML](http://rapidxml.sourceforge.net/) library (version 1.13)
  * [Boost](http://www.boost.org/) library

## Building the tool
To build *AclCheck* you need to satisfy all of the following build requirements.

### Build requirements
  * [GNU C++ compiler](http://gcc.gnu.org/) (g++)
  * [GNU Make](http://www.gnu.org/software/make/) (make)
  * installed [Boost](http://www.boost.org/) library in system headers location

### Building process
To build binary using make tool, you can use some of the following Makefile options.

  * **make** - command compiles binary of the tool which is using optimized algorithm based on tries (binary name *AclCheck*) and it also compiles binary of the tool which is using naive algorithm (binary name *AclCheckNaive*).

  * **make all** - command compiles binary of the tool which is using optimized algorithm based on tries (binary name *AclCheck*) and it also compiles binary of the tool which is using naive algorithm (binary name *AclCheckNaive*).

  * **make tool** - command compiles binary of the tool which is using optimized algorithm based on tries (binary name *AclCheck*).

  * **make naive** - command compiles binary of the tool which is using naive algorithm (binary name *AclCheckNaive*).

  * **make debug** - command compiles binary of the tool which is using optimized algorithm based on tries (binary name *AclCheck*), using also debug library. This binary is useful for debugging purposes.

  * **make clean** - command removed all temporary files, compiled binaries and default analysis file, if there is any.

### GIT repository
This is a clone of the [original repository on code.google.com](https://code.google.com/p/acl-check/), since Google is shutting down the service.

Repository contains:
  * Tool source codes.
  * Testing ACLs.
  * Source code documentation generated using [Doxygen](http://www.stack.nl/~dimitri/doxygen/index.html).
  * Source codes of the *RapidXml* library.

## How to use it
*AclCheck* is a console application without interactive prompt. Various options can be specified using the application arguments. Some of them are mandatory, some are optional and if not set, default values are used.

### Available arguments
  * **-i <input_file>** - argument used for specifying input file with ACLs to analyse. This argument is mandatory!

  * **-o <output_file>** - argument used for specifying output file name to which analysis results are written. This argument is optional and if not set, file name `result.xml` is used. 

  * **-f <input_format>** - argument used for specifying format of the input file. This argument is optional and if not set, Cisco format configuration is assumed. As input format can be used:
    * **cisco** - configuration file of a Cisco device.
    * **hp** - configuration file of a HP device.
    * **juniper** - firewall configuration of a Juniper device in XML format.
    * **xml** - simple XML format of ACL configurations used for testing the tool in the beginning.
    * **bench** - format used for ACL configuration used by generator from [ClassBench project](http://www.arl.wustl.edu/classbench/index.htm).

  * To specify output file detail level, you can use one of four following arguments. You can use only one of them, but don't have to use any. If no detail level argument is used, detail level 2 is assumed. You can use following detail level arguments:
    * **-1** - detail level 1. Output file contains: names of analysed ACLs; type of conflict between rules; positions (names) of ACL rules.
    * **-2** - detail level 2. Output file contains: names of analysed ACLs; type of conflict between rules; positions (names) of ACL rules; communication protocols; source IPv4 ranges; rules actions.
    * **-3** - detail level 3. Output file contains: names of analysed ACLs; type of conflict between rules; positions (names) of ACL rules; communication protocols; source IPv4 ranges; source ports ranges; destination IPv4 ranges; destination ports ranges; rules actions.
    * **-4** - detail level 4. Output file contains: names of analysed ACLs; type of conflict between rules; positions (names) of ACL rules; communication protocols; source IPv4 ranges; source ports ranges; destination IPv4 ranges; destination ports ranges; rules actions. Output file additionally contains also relations between corresponding ACL rule dimensions (fields). 

  * **-h** - argument used to print program help to the standard output. Argument is optional.

  * **-v** - argument used to make command line output of the tool verbose. It additionally prints parsed ACLs and their rules. Argument is optional.

Example:
  * Command to analyse ACLs in configuration of a HP network device saved in file named *hp_conf*, with additional verbose output and output file detail level 3:
```
./aclCheck –i hp_conf –v -3 –f hp
```

## Tool Output
Output of the input file analysis is a XML document. It contains number of information depending on set output file detail level. Examples of XML documents for each detail level follows.

### Detail Level 1
```xml
<?xml version="1.0" encoding="utf-8"?>
<AclCheck-analysis output-detail="1">
   <access-list id="Acl">
      <conflict type="correlation">
         <ruleX name="0"/>
         <ruleY name="6"/>
      </conflict>
   </access-list>
</AclCheck-analysis>
```

### Detail Level 2
```xml
<?xml version="1.0" encoding="utf-8"?>
<AclCheck-analysis output-detail="2">
   <access-list id="Acl">
      <conflict type="correlation">
         <ruleX name="0" proto="tcp" srcIP="176.71.153.32-240.71.221.33" action="deny"/>
         <ruleY name="6" proto="tcp" srcIP="128.75.1.50-192.91.213.178" action="permit"/>
      </conflict>
   </access-list>
</AclCheck-analysis>
```

### Detail Level 3
```xml
<?xml version="1.0" encoding="utf-8"?>
<AclCheck-analysis output-detail="3">
   <access-list id="Acl">
      <conflict type="correlation">
         <ruleX name="0" proto="tcp" srcIP="176.71.153.32-240.71.221.33" srcPort="any" dstIP="88.0.32.137-121.36.123.201" dstPort="any" action="deny"/>
         <ruleY name="6" proto="tcp" srcIP="128.75.1.50-192.91.213.178" srcPort="any" dstIP="27.0.128.6-155.36.148.207" dstPort="any" action="permit"/>
      </conflict>
   </access-list>
</AclCheck-analysis>
```

### Detail Level 4
```xml
<?xml version="1.0" encoding="utf-8"?>
<AclCheck-analysis output-detail="4">
   <access-list id="Acl">
      <conflict type="correlation">
         <ruleX name="0" proto="tcp" srcIP="176.71.153.32-240.71.221.33" srcPort="any" dstIP="88.0.32.137-121.36.123.201" dstPort="any" action="deny"/>
         <ruleY name="6" proto="tcp" srcIP="128.75.1.50-192.91.213.178" srcPort="any" dstIP="27.0.128.6-155.36.148.207" dstPort="any" action="permit"/>
         <relation proto="Y_equivalent_X" srcIP="Y_interleaving_X" srcPort="Y_equivalent_X" dstIP="Y_superset_of_X" dstPort="Y_equivalent_X"/>
      </conflict>
   </access-list>
</AclCheck-analysis>
```
