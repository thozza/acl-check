# AclCheck - simple tool for static analysis of ACLs in network device configuration.
# Copyright (C) 2012  Tomas Hozza
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#
# Makefile for building ACL check tool

CC=g++
ARGS=-Wall -pedantic -ansi -O1 -fpermissive
DARGS=-ggdb3 -Wall -pedantic -ansi -fpermissive
OUT=-o aclCheck
OUT1=-o aclCheckNaive

all: tool naive

tool: main.cpp WAHBitVector.hpp WAHBitVector.cpp AclRule.hpp AclRule.cpp AccessControlList.hpp AccessControlList.cpp ProtocolsDef.hpp PortsDef.hpp GlobalDefs.hpp PrefixTree.hpp PrefixTree.cpp PrefixForest.hpp PrefixForest.cpp Exception.hpp Exception.cpp InputParser.hpp XmlInputParser.hpp XmlInputParser.cpp CiscoInputParser.hpp CiscoInputParser.cpp HpInputParser.hpp HpInputParser.cpp JuniperInputParser.hpp JuniperInputParser.cpp ClassBenchInputParser.hpp ClassBenchInputParser.cpp XmlOutputWriter.hpp XmlOutputWriter.cpp Conflict.hpp Conflict.cpp rapidxml/rapidxml.hpp
	$(CC) $(ARGS) $(OUT) main.cpp WAHBitVector.cpp AclRule.cpp AccessControlList.cpp PrefixTree.cpp PrefixForest.cpp Exception.cpp XmlInputParser.cpp CiscoInputParser.cpp HpInputParser.cpp JuniperInputParser.cpp ClassBenchInputParser.cpp XmlOutputWriter.cpp Conflict.cpp

debug: main.cpp WAHBitVector.hpp WAHBitVector.cpp AclRule.hpp AclRule.cpp AccessControlList.hpp AccessControlList.cpp ProtocolsDef.hpp PortsDef.hpp GlobalDefs.hpp PrefixTree.hpp PrefixTree.cpp PrefixForest.hpp PrefixForest.cpp Exception.hpp Exception.cpp InputParser.hpp XmlInputParser.hpp XmlInputParser.cpp CiscoInputParser.hpp CiscoInputParser.cpp HpInputParser.hpp HpInputParser.cpp JuniperInputParser.hpp JuniperInputParser.cpp ClassBenchInputParser.hpp ClassBenchInputParser.cpp XmlOutputWriter.hpp XmlOutputWriter.cpp Conflict.hpp Conflict.cpp rapidxml/rapidxml.hpp
	$(CC) $(DARGS) $(OUT) main.cpp WAHBitVector.cpp AclRule.cpp AccessControlList.cpp PrefixTree.cpp PrefixForest.cpp Exception.cpp XmlInputParser.cpp CiscoInputParser.cpp HpInputParser.cpp JuniperInputParser.cpp ClassBenchInputParser.cpp XmlOutputWriter.cpp Conflict.cpp

naive: main2.cpp WAHBitVector.hpp WAHBitVector.cpp AclRule.hpp AclRule.cpp AccessControlList.hpp AccessControlList.cpp ProtocolsDef.hpp PortsDef.hpp GlobalDefs.hpp PrefixTree.hpp PrefixTree.cpp PrefixForest.hpp PrefixForest.cpp Exception.hpp Exception.cpp InputParser.hpp XmlInputParser.hpp XmlInputParser.cpp CiscoInputParser.hpp CiscoInputParser.cpp HpInputParser.hpp HpInputParser.cpp JuniperInputParser.hpp JuniperInputParser.cpp ClassBenchInputParser.hpp ClassBenchInputParser.cpp XmlOutputWriter.hpp XmlOutputWriter.cpp Conflict.hpp Conflict.cpp rapidxml/rapidxml.hpp
	$(CC) $(ARGS) $(OUT1) main2.cpp WAHBitVector.cpp AclRule.cpp AccessControlList.cpp PrefixTree.cpp PrefixForest.cpp Exception.cpp XmlInputParser.cpp CiscoInputParser.cpp HpInputParser.cpp JuniperInputParser.cpp ClassBenchInputParser.cpp XmlOutputWriter.cpp Conflict.cpp

clean:
	rm -f aclCheck
	rm -f aclCheckNaive
	rm -f result.xml
	rm -f *~
