#ifndef H_CFGRECOVERY_H
#define H_CFGRECOVERY_H
       
#include <vector>
#include <set>
#include <map>
#include <queue>

#include <string.h>
using namespace std;

#include "pro.h"
#include "ida.hpp"
#include "idp.hpp"
#include "ua.hpp"

#include "H_pcode.h"

#include "cfg.h"

#define flow_ordinary   0x15   // ordinary flow ¿¿¿¿¿¿¿¿¿¿¿¿

class CBasicBlock  
{
public:
    int  n;                   
    uint64_t first;               // va of the 1st instruction in the bb 

    vector<PCode> codes;          // va for instructions 

    vector<uint64_t>  cref_from;  // bbs referencing this bb
    vector<uint64_t>  cref_to;    // bbs referenced by this bb

public:
    CBasicBlock()        
    {
    }// end of CBasicBlock()

    ~CBasicBlock()
    {
    }// end of ~CBasicBlock()
};


class CFuncBBManager
{
private:
    /* --------------------------------------------------------- */
    set<uint64_t>               path_mark;    // ¿¿¿¿¿¿ bb ¿
    set<uint64_t>    	        future_label; // ¿¿¿¿¿¿ bb ¿
    vector<uint64_t>            nodes;        
    map<uint64_t,uint64_t> 	exit2entry;

    map<uint64_t,CBasicBlock *> bbs;          // basic blocks
    int 	  	        bb_num;
    /* --------------------------------------------------------- */

    map<uint64_t, BasicBlock *> gen_bbs;

    void gather_ida_basic_blocks(uint64_t entry);

    BasicBlock * generate_cfg_bb( Cfg         * cfg,
				  CBasicBlock * bblock,
				  bool          isEntry
				);

    void generate_all_bbs( Cfg * cfg,
			   uint64_t  func_entry
			 );

    void generate_bb_links( Cfg * cfg,
			    uint64_t  func_entry
			  );


public:
    CFuncBBManager();

    ~CFuncBBManager();

    void generate_cfg(Cfg * cfg, uint64_t entry);
};

#endif
