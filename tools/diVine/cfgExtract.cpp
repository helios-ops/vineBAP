#include <stdio.h>
#include <sstream>
#include <string>

#include "binaryCFG.h"
#include "IRRecoveryManager.h"

using namespace vmi;
using namespace llvm;

bool IRRecoveryManager::ParseBBInfoFile() 
{
    const unsigned MAX_LINE = 512;
    char line[MAX_LINE];

    FILE *fp = fopen(m_fn_bbinfo.c_str(), "r");
    if (!fp) 
    {
        llvm::errs() << "Could not open " << m_fn_bbinfo << "\n";
        return false;
    }

    while (fgets(line, MAX_LINE, fp)) 
    {
        std::istringstream ss(line);
        std::string start, end, size, type_str, target_str;
        ss >> start >> end >> size >> type_str >> target_str;

        if (type_str == "c") 
	{
            // Insert a call block
            m_org_bbs.insert( new BinaryBasicBlock( strtol(start.c_str(), NULL, 0), 
				                    strtol(end.c_str(), NULL, 0),
                                              	    strtol(size.c_str(), NULL, 0), 
					            strtol(target_str.c_str(), NULL, 0)
					          )
		            );
        } 
	else 
	{
            // Insert a normal block
            m_org_bbs.insert( new BinaryBasicBlock( strtol(start.c_str(), NULL, 0), 
				    	            strtol(end.c_str(), NULL, 0),
                                                    strtol(size.c_str(), NULL, 0)
					          )
	 	            );
        }
    }

    fclose(fp);
    return true;
}


bool IRRecoveryManager::ParseCfgFile() 
{
    const unsigned MAX_LINE = 512;
    char line[MAX_LINE];

    FILE *fp = fopen(m_fn_cfginfo.c_str(), "r");
    if (!fp) 
    {
        llvm::errs() << "Could not open " << m_fn_cfginfo << "\n";
        return false;
    }

    BinaryFunction *currentFunction = NULL;

    while (fgets(line, MAX_LINE, fp)) 
    {
        std::istringstream ss(line);

        if (strstr(line, "function")) 
	{
            std::string dummy, address_str, function_name;
            uint64_t address;
            ss >> dummy >> address_str >> function_name;

            if (function_name.size() == 0) {
                function_name = "<unknown>";
            }

            address = strtol(address_str.c_str(), NULL, 0);

            BinaryBasicBlock *bb = m_org_bbs.find(address);
            assert(bb && "Could not find entry point basic block");

            currentFunction = new BinaryFunction(function_name, bb);
	    m_org_funcs[address] = currentFunction;

	    m_divine_funcs[address] = new Function( function_name,
			    			    address,
						    0,
						    m_modName
			    			  );
        } 
	else 
	{
            std::string bb_str;
            uint64_t bb_addr;

            ss >> bb_str;
            bb_addr = strtol(bb_str.c_str(), NULL, 0);
            if (!bb_addr) {
                continue;
            }

            BinaryBasicBlock *bb = m_org_bbs.find(bb_addr);
            if (!bb) 
	    {
                llvm::errs() << "Warning: bb " << hexval(bb_addr) << " is undefined\n";
                continue;
            }

            BinaryBasicBlock::Children succs;
            while (!ss.eof()) {
                std::string edge_str;
                uint64_t edge_addr = 0;
                ss >> edge_str;
                edge_addr = strtol(edge_str.c_str(), NULL, 0);
                if (!edge_addr) {
                    continue;
                }

                BinaryBasicBlock *edge = m_org_bbs.find(edge_addr);
                if (edge) 
		{
                    succs.push_back(edge);
                }
            }

            currentFunction->add(bb, succs);
        }
    }

    fclose(fp);
    return true;
}



