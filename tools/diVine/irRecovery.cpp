#include <set>
#include <vector>
#include <string>
#include <queue>
#include <inttypes.h>
#include <sstream>
#include <stdio.h>
#include <capstone/capstone.h>

#include "cfg.h"
#include "vmi/include/ElfDwarf.h"
#include "vmi/include/ExecutableFile.h"
#include "vmi/include/Vmi.h"

#include "binaryCFG.h"
#include "IRRecoveryManager.h"

using namespace vmi;


std::string IRRecoveryManager::filename(const std::string& path)
{
    return path.substr(path.find_last_of("/\\") + 1);
}


IRRecoveryManager::IRRecoveryManager( std::string & fn_exe,
	    	      		      std::string & fn_bbinfo,
	    	       		      std::string & fn_cfginfo,
				      std::string & dot
	    	     		    )
{
    m_fn_exe     = fn_exe;
    m_modName    = filename(m_fn_exe); 

    m_fn_bbinfo  = fn_bbinfo;
    m_fn_cfginfo = fn_cfginfo;

    m_dot        = dot;
}


bool IRRecoveryManager::init()
{
    m_fp = FileSystemFileProvider::get(m_fn_exe, false);
    if (!m_fp) 
    {
        llvm::errs() << "Could not open " << m_fn_exe << "\n";
        return false;
    }

    m_exec = ExecutableFile::get(m_fp, false, 0);
    if (!m_exec) 
    {
        llvm::errs() << "ExecutableFile::get() failed for " << m_fn_exe << "\n";
	return false;
    }

    if (!ParseBBInfoFile())
    {
	return false;
    }

    if (!ParseCfgFile())
    {
	return false;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_handle) != CS_ERR_OK)
    {
	llvm::errs() << "capstone: cs_open() error !\n";
	return false;
    }

    return true;
}


IRRecoveryManager::~IRRecoveryManager()
{
    if (m_exec)
    {
	delete m_exec;
    }

    if (m_handle)
    {
	cs_close(&m_handle);
    }
}


BasicBlock * IRRecoveryManager::generate_divine_cfg_bb( Cfg              * cfg,
						        BinaryBasicBlock * bblock,
				                        bool               isEntry
					              )
{
    BasicBlock * bb = cfg->addBasicBlock(bblock->startPc);

    char     insn_buf[1024];
    uint64_t insn_addr = bblock->startPc;
    ssize_t  insn_size = bblock->size;

    cs_insn * my_insns;

    Instruction * insn = NULL;

    if (isEntry)
    {
	cfg->setEntry(bb);
    }

    printf("block : startPc = %lx, size = %d\n", bblock->startPc, bblock->size);

    m_exec->read(insn_buf, bblock->size, bblock->startPc);

    size_t insn_count = cs_disasm( m_handle, 
                                   (uint8_t *)insn_buf, 
                                   insn_size,  // maximum size 
                                   insn_addr, 
                                   0, 
                                   &my_insns
                                 );

    // 将本 bb 的所有指令添加进来
    for (int i = 0; i < insn_count; i++)
    {
	insn = new Instruction( my_insns[i].address,
				my_insns[i].bytes,
				my_insns[i].size
			      );
	bb->addInstruction(insn);
    }

    // 根据本 bb 的最后一条指令是否为 ret，判定当前基本块是否是函数的 exit-bb
    // HHui NOTE: 这里本来可以直接比对 x86 平台 ret 指令的字节码。此处基于中间语言的判定，旨在让代码适应更多的目标平台
    insn->decode();
    if (insn->isReturn())
    {
	(cfg->exits).insert(bb);
    }

    cs_free(my_insns, insn_count);

    return bb;
}


void IRRecoveryManager::generate_divine_func_bbs( Cfg            * cfg,
						  BinaryFunction * func
				                )
{
    std::queue<BinaryBasicBlock *> workset;
    std::set<uint64_t>             analyzed_set;

    BasicBlock       * outbb    = NULL;
    BinaryBasicBlock * curr_bbb = func->getEntryBlock();

    uint64_t entry_addr = curr_bbb->startPc;
    uint64_t addr = 0;

    workset.push(curr_bbb);

    while (!workset.empty())
    {
	curr_bbb = (BinaryBasicBlock *)(workset.front()); 
	addr     = curr_bbb->startPc;

	workset.pop();

	if (addr == entry_addr)
	{
	    outbb = generate_divine_cfg_bb(cfg, curr_bbb, true);
	}
	else
	{
	    outbb = generate_divine_cfg_bb(cfg, curr_bbb, false);
	}

	analyzed_set.insert(curr_bbb->startPc);
	m_divine_bbs[addr] = outbb; 

	// 将后继基本块们添加到工作集中
	for ( BinaryBasicBlock::succ_iterator it = curr_bbb->succ_begin(); 
	      it != curr_bbb->succ_end(); 
	      ++it
	    ) 
	{
	    BinaryBasicBlock * next_bbb = *it;
	    if (analyzed_set.count(next_bbb->startPc) == 0)
	    {
		workset.push(next_bbb);
	    }
       }
    }
}


BasicBlock * IRRecoveryManager::BBB_to_BB(BinaryBasicBlock * bbb)
{
    uint64_t addr = bbb->startPc;
    if (m_divine_bbs.find(addr) == m_divine_bbs.end())
    {
	return NULL;
    }
    return m_divine_bbs[addr];
}


Function * IRRecoveryManager::BF_to_F(BinaryFunction * bf)
{
    uint64_t addr = bf->getEntryBlock()->startPc;
    if (m_divine_funcs.find(addr) == m_divine_funcs.end())
    {
	return NULL;
    }
    return m_divine_funcs[addr];
}


void IRRecoveryManager::generate_divine_func_bb_links( Cfg            * cfg,
						       BinaryFunction * func
				                     )
{
    std::queue<BinaryBasicBlock *> workset;
    std::set<uint64_t>             analyzed_set;

    BinaryBasicBlock * curr_bbb = func->getEntryBlock();

    workset.push(curr_bbb);

    BasicBlock * srcbb = NULL;
    BasicBlock * dstbb = NULL;

    while (!workset.empty())
    {
	curr_bbb = (BinaryBasicBlock *)(workset.front()); 
	workset.pop();

	srcbb = BBB_to_BB(curr_bbb);

	// 在当前 bb 和其后继 bb 之间建立边
	for ( BinaryBasicBlock::succ_iterator it = curr_bbb->succ_begin(); 
	      it != curr_bbb->succ_end(); 
	      it ++
	    ) 
	{
	    BinaryBasicBlock * next_bbb = *it;
	    if (analyzed_set.count(next_bbb->startPc) == 0)
	    {
		workset.push(next_bbb);
	    }

	    dstbb = BBB_to_BB(next_bbb);
	    cfg->linkBasicBlocks(srcbb, dstbb);
	}

	analyzed_set.insert(curr_bbb->startPc);
    }
}


void IRRecoveryManager::generate_cfg_for_function( Function       * divine_func, 
				      	           BinaryFunction * func
				                 )
{
    Cfg * cfg = divine_func->getCfg();

    generate_divine_func_bbs( cfg,
			      func
			    );

    generate_divine_func_bb_links( cfg,
				   func
	    			 );
}


void IRRecoveryManager::generate_divine_cfgs()
{

    for ( std::map<uint64_t, Function *>::iterator iter = m_divine_funcs.begin();
	  iter != m_divine_funcs.end();
	  iter ++
	)
    {
	generate_cfg_for_function( iter->second,
				   m_org_funcs[iter->first] 
				 );
    }
}



void IRRecoveryManager::print_graph_divine_cfgs()
{
    FILE * f = NULL;
    char tmp[PATH_MAX];

    for ( std::map<uint64_t, Function *>::iterator it = m_divine_funcs.begin(); 
	  it != m_divine_funcs.end(); 
	  it++
	) 
    {
	Function *func = it->second;
	
	snprintf( tmp, 
  		  sizeof(tmp) - 1, 
		  "%s/%lx.dot", 
		  m_dot.c_str(), 
		  func->getAddress()
		);
	    
	tmp[sizeof(tmp) - 1] = '\0';
	
    	
    	f = fopen(tmp, "w+");
	printf("noew try to generate dot file ---  %s\n", tmp);
	assert(f);
	fprintf(f, "%s", func->getCfg()->dot().c_str());
	fclose(f);

    }


    // Test decoding
    // func->getCfg()->decode();
    // Test dominators
    // func->getCfg()->computeDominators();
    // Test iterator
    // for (Cfg::bb_const_iterator bbit = func->getCfg()->bb_begin(); 
    //      bbit != func->getCfg()->bb_end(); bbit++) {
    //	debug2("BBIT: %.8x\n", (*bbit)->getAddress());
    // }

    /*
    if (dot) 
    {
	printf("dot file generated !\n");
	snprintf(tmp, sizeof(tmp) - 1, "%s/callgraph.dot", dot);
	tmp[sizeof(tmp) - 1] = '\0';
	f = fopen(tmp, "w");
	assert(f);
	fprintf(f, "%s", callgraph->dot().c_str());
	fclose(f);
    }
    */


}
