#ifndef H_IR_RECOVERY_MANAGER_H
#define H_IR_RECOVERY_MANAGER_H

#include <map>

#include <capstone/capstone.h>
#include "binaryCFG.h"

#include "cfg.h"

#include "vmi/include/ElfDwarf.h"
#include "vmi/include/ExecutableFile.h"
#include "vmi/include/Vmi.h"

 
using namespace vmi;
using namespace llvm;

class IRRecoveryManager
{
    csh         m_handle;

    std::string m_modName;

    std::string m_dot;

    std::string m_fn_exe;
    std::string m_fn_bbinfo;
    std::string m_fn_cfginfo;

    BinaryBasicBlocks m_org_bbs;
    std::map<uint64_t, BinaryFunction *> m_org_funcs;

    FileSystemFileProvider * m_fp;
    ExecutableFile         * m_exec;

    std::map<uint64_t, Function *>   m_divine_funcs;
    std::map<uint64_t, BasicBlock *> m_divine_bbs;


    std::string filename(const std::string& path);

    // IR-cfg generation utils 
    BasicBlock * generate_divine_cfg_bb( Cfg              * cfg,
					 BinaryBasicBlock * bblock,
				         bool               isEntry
				       );

    void generate_divine_func_bbs( Cfg            * cfg,
				   BinaryFunction * func
				 );

    BasicBlock * BBB_to_BB(BinaryBasicBlock * bbb);

    Function * BF_to_F(BinaryFunction * bf);

    void generate_divine_func_bb_links( Cfg            * cfg,
					BinaryFunction * func
				      );

    void generate_cfg_for_function( Function       * divine_func, 
				    BinaryFunction * func
				  );


    // cfg extraction utils
    bool ParseBBInfoFile();

    bool ParseCfgFile();

public:
    IRRecoveryManager( std::string & fn_exe,
	    	       std::string & fn_bbinfo,
	    	       std::string & fn_cfginfo,
		       std::string & dot
	    	     );

    ~IRRecoveryManager();

    bool init();

    // generate diVine's cfg 
    void generate_divine_cfgs();

    void print_graph_divine_cfgs();
};


#endif
