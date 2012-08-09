/*
 * AclCheck - simple tool for static analysis of ACLs in network device configuration.
 * Copyright (C) 2012  Tomas Hozza
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

//#define TEST

#include <unistd.h>
#include <sys/time.h>
#include <memory>
#include <iostream>
#include <fstream>

/****** INPUT MODULES ******/
#include "InputParser.hpp"
#include "XmlInputParser.hpp"
#include "CiscoInputParser.hpp"
#include "HpInputParser.hpp"
#include "JuniperInputParser.hpp"
#include "ClassBenchInputParser.hpp"
/****** APP MODULES ******/
#include "AclRule.hpp"
#include "AccessControlList.hpp"
#include "PrefixForest.hpp"
#include "Conflict.hpp"
/****** OUTPUT MODULES ******/
#include "OutputWriter.hpp"
#include "XmlOutputWriter.hpp"

using namespace std;

const int INPUT_FORMAT_CISCO = 1;
const int INPUT_FORMAT_HP = 2;
const int INPUT_FORMAT_JUNIPER = 3;
const int INPUT_FORMAT_XML = 4;
const int INPUT_FORMAT_CLASSBENCH = 5;

const char* DEFAULT_OUTPUT_FILE = "result.xml";

/**
 * Print program usage.
 *
 * @param prog pointer to string containing program name.
 */
static void usage(char* prog)
{
    cout << prog << "  Copyright (C) 2012  Tomas Hozza" << endl;
    cout << "This program comes with ABSOLUTELY NO WARRANTY." << endl;
    cout << "This is free software, and you are welcome to redistribute it" << endl;
    cout << "under conditions of the GNU/GPLv3 license." << endl;
    cout << "---------------------------------------------------------------------------------" << endl;
    cout << "PROGRAM USAGE:" << endl;
    cout << " -i <input_file>\tSet input file with device/acl configuration." << endl;
    cout << "\t\t\tThis parameter is REQUIRED!" << endl << endl;
    cout << " -o <output_file>\tSet output file name with results." << endl;
    cout << "\t\t\tThis parameter is optional. If not set, \"result.xml\" filename is used." << endl << endl;
    cout << " -f <input_format>\tSet format of input configuration file. This parameter is optional." << endl;
    cout << "\t\t\tPossible input formats are: \"cisco\", \"hp\", \"juniper\", \"xml\", \"bench\"." << endl;
    cout << "\t\t\tIf not set, \"cisco\" configuration format is used." << endl << endl;
    cout << "OUTPUT FILE DETAIL OPTIONS:" << endl;
    cout << " -1\tDETAIL 1 - Output contains: conflict type; conflict rules names/positions." << endl;
    cout << " -2\tDETAIL 2 - Output contains: same as DETAIL 1 + protocol; source IP; action." << endl;
    cout << " -3\tDETAIL 3 - Output contains: same as DETAIL 2 + source port, destination IP, destination port." << endl;
    cout << " -4\tDETAIL 4 - Output contains: same as DETAIL 3 + relations between conflicting rules dimensions." << endl;
    cout << "\tThis parameter is optional. If not set, DETAIL 2 is used." << endl << endl;
    cout << " -h\tPrint this help/usage." << endl << endl;
    cout << " -v\tPrint rules of each analysed Access Control List." << endl << endl;
}

//--------------------------------------------------------------------------------

/**
 * Method converts the constant representing the configuration format to corresponding string.
 *
 * @param type constant representing the configuration format INPUT_FORMAT_XXX.
 * @return string representing the configuration format.
 */
static string confTypeToString(int type)
{
    switch ( type )
    {
        case INPUT_FORMAT_CISCO:
            return string("Cisco");

        case INPUT_FORMAT_CLASSBENCH:
            return string("Class Bench");

        case INPUT_FORMAT_HP:
            return string("HP");

        case INPUT_FORMAT_JUNIPER:
            return string("Juniper");

        case INPUT_FORMAT_XML:
            return string("XML");

        default:
            return string("unknown format");
    }
}

//--------------------------------------------------------------------------------

/**
 * Main function.
 *
 * @param argc number of program parameters.
 * @param argv parameters of the program.
 * @return 0 - if program ended ok.
 *         1 - if error occured.
 */
int main(int argc, char* argv[])
{
    auto_ptr< InputParser > m_inputParser;
    auto_ptr< OutputWriter > m_outputWriter;
    ifstream f_inputFile;
    ofstream f_outputFile;

    bool m_verboseMode = false;
    int m_outputDetail = OUTPUT_DETAIL_2;
    int m_inputFormat = INPUT_FORMAT_CISCO;
    char* m_inputFileName = NULL;
    char* m_outputFileName = NULL;

    auto_ptr< boost::ptr_vector< AccessControlList > > m_parsedAcls;

    //-----------------------------------------------------------------------------------
    
    /* arguments's check */
    if (argc < 2)
    {
        cerr << argv[0] << " ERROR: Too few arguments!" << endl;
        usage(argv[0]);
        return 1;
    }

    int c;
    /***** GETOPT *****/
    while ( (c = getopt(argc, argv, "i:o:f:1234hv")) != -1 )
    {
        switch ( c )
        {
            /* input file */
            case 'i':
                m_inputFileName = optarg;
                break;
                
            /* output file */
            case 'o':
                m_outputFileName = optarg;
                break;

            /* input format */
            case 'f':
                if ( strcmp(optarg, "juniper") == 0 )
                    m_inputFormat = INPUT_FORMAT_JUNIPER;
                else if ( strcmp(optarg, "hp") == 0 )
                    m_inputFormat = INPUT_FORMAT_HP;
                else if ( strcmp(optarg, "xml") == 0 )
                    m_inputFormat = INPUT_FORMAT_XML;
                else if ( strcmp(optarg, "bench") == 0 )
                    m_inputFormat = INPUT_FORMAT_CLASSBENCH;
                break;
                
            /* output detail */
            case '1':
                m_outputDetail = OUTPUT_DETAIL_1;
                break;
            case '2':
                m_outputDetail = OUTPUT_DETAIL_2;
                break;
            case '3':
                m_outputDetail = OUTPUT_DETAIL_3;
                break;
            case '4':
                m_outputDetail = OUTPUT_DETAIL_4;
                break;

            /* print usage */
            case 'h':
                usage(argv[0]);
                return 0;

            case 'v':
                m_verboseMode = true;
                break;

            default:
                cerr << argv[0] << " ERROR: Unknown argument \"" << (char)c << "\"!" << endl;
                usage(argv[0]);
                return 1;
        }
    }

    cout << "Input File = \"" << m_inputFileName << "\"" << endl;
    cout << "Input File Format = \"" << confTypeToString(m_inputFormat) << "\"" << endl;
    
    if ( m_outputFileName == NULL )
        cout << "Output File = \"" << DEFAULT_OUTPUT_FILE << "\"" << endl;
    else
        cout << "Output File = \"" << m_outputFileName << "\"" << endl;

    cout << "Output Detail Level = \"" << m_outputDetail << "\"" << endl;

    //-----------------------------------------------------------------------------------
    
    /****** INPUT ******/
    if ( m_inputFileName == NULL )
    {
        cerr << argv[0] << " ERROR: No input file name specified!" << endl;
        usage(argv[0]);
        return 1;
    }

    f_inputFile.open(m_inputFileName, ios_base::in);

    if ( !f_inputFile.is_open() )
    {
        cerr << argv[0] << " ERROR: Can't open input file \"" << m_inputFileName << "\"!" << endl;
        return 1;
    }

    /* create proper input parser */
    switch ( m_inputFormat )
    {
        case INPUT_FORMAT_HP:
            m_inputParser = auto_ptr< InputParser >(new HpInputParser());
            break;
            
        case INPUT_FORMAT_CISCO:
            m_inputParser = auto_ptr< InputParser >(new CiscoInputParser());
            break;

        case INPUT_FORMAT_JUNIPER:
            m_inputParser = auto_ptr< InputParser >(new JuniperInputParser());
            break;

        case INPUT_FORMAT_XML:
            m_inputParser = auto_ptr< InputParser >(new XmlInputParser());
            break;

        case INPUT_FORMAT_CLASSBENCH:
            m_inputParser = auto_ptr< InputParser >(new ClassBenchInputParser());
            break;
    }

    try {
        m_parsedAcls = m_inputParser->parse(f_inputFile);
    }
    catch ( Exception e )
    {
        cerr << argv[0] << " ERROR: Parsing of input file failed!" << endl;
        cerr << argv[0] << e.toString();

        f_inputFile.close();
        return 1;
    }
    f_inputFile.close();

    cout << "Number of parsed ACLs = " << m_parsedAcls->size() << endl;
    //-----------------------------------------------------------------------------------

    /****** OUTPUT ******/
    if ( m_outputFileName == NULL )
        f_outputFile.open(DEFAULT_OUTPUT_FILE, std::_S_trunc);
    else
        f_outputFile.open(m_outputFileName, std::_S_trunc);

    if ( !f_outputFile.is_open() )
    {
        cerr << argv[0] << " ERROR: Can't create output file!" << endl;
        return 1;
    }
    
    m_outputWriter = auto_ptr< OutputWriter >(new XmlOutputWriter(f_outputFile, m_outputDetail));

    #ifdef TEST
    struct timeval start;
    gettimeofday(&start, NULL);
    #endif
    
    /****** PROCESSING ******/
    size_t size = m_parsedAcls->size();
    for ( size_t i = 0; i < size; ++i )
    {
        AccessControlList* actualACL = &(*m_parsedAcls)[i];

        if ( m_verboseMode )
        {
            cout << endl << *actualACL << endl;
        }
        
        int numOfrules = actualACL->size();
        auto_ptr< PrefixForest > aclPrefixForest(new PrefixForest(numOfrules));

        m_outputWriter->writeNewACL(actualACL->name());

        #ifdef TEST
        cout << "" << numOfrules << endl;
        unsigned long numOfAnalyzations = 0;
        unsigned long numOfConflicts = 0;
        #endif
        
        for ( int j = 0; j < numOfrules; ++j )
        {
            AclRule* actualRule = &(*actualACL)[j];
            auto_ptr< WAHBitVector > actualConfVector(aclPrefixForest->addAclRule(*actualRule));
            
            WAHBitVector::OnesIterator it = actualConfVector->getOnesIterator(actualRule->getPosition());

            int32_t pos = -1;
            while ( (pos = it.next()) != -1 )
            {
                #ifdef TEST
                ++numOfAnalyzations;
                #endif

                auto_ptr< Conflict > conf = Conflict::classifyConflict((*actualACL)[pos], *actualRule);

                if (conf.get()->isConflict())
                {
                    #ifdef TEST
                    ++numOfConflicts;
                    #endif
                    
                     m_outputWriter->writeNewConflict(*conf);
                }
            }
        }

        #ifdef TEST
        struct timeval stop;
        gettimeofday(&stop, NULL);
        
        cout << "" << numOfAnalyzations << endl;
        cout << "" << numOfConflicts << endl;
        cout.setf(ios_base::fixed, ios_base::floatfield);
        cout << "" << (double(stop.tv_sec - start.tv_sec)) + (double(stop.tv_usec - start.tv_usec) / 1000000) << endl;
        #endif
    }

    m_outputWriter->flush();    /* flush results to output file */
    f_outputFile.close();
    
    return 0;
}
