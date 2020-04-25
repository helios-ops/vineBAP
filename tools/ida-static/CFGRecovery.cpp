#include "stdlib.h"

#include "H_pcode.h"
#include "CFGRecovery.h"



CFuncBBManager::CFuncBBManager()
{
}


CFuncBBManager::~CFuncBBManager()
{
    for ( map<uint64_t, CBasicBlock *>::iterator iter = bbs.begin();
	  iter != bbs.end();
	  iter ++
	)
    {
	free(iter->second);
    }
}


void CFuncBBManager::gather_ida_basic_blocks(uint64_t entry)
{
    // 从 entry 开始分析 basic-block，结果储存到 bbs

    uint64_t  start = entry;
    uint64_t  curr, next, prev;
    uint64_t  next_entry; // 下一个分析地址
    PCode pcode;
    CBasicBlock * bb = new CBasicBlock();

    if (!isCode(get_flags_novalue(start)))
    {  
        msg("invalid entry\n"); //entry != 代码
        return;
    }// end of if()
    
    show_wait_box("Searching basic blocks...\n\n\nJust a Moment");

    bbs.clear();
    exit2entry.clear();    

    path_mark.clear();
    future_label.clear();

    // bb_num = 0;
    bb_num = 1;
 
__Analysis:

    if(wasBreak()) 
    {
	goto __Exit; // 用户取消
    }// end of if()

    if(path_mark.count(start)) // 已经分析过 start
    {
        goto __FutureLabel;
    }
    else 
    {
	path_mark.insert(start); // 设置 “已分析过” 标记
    }// end of if()


    (bb->codes).clear(); // 初始化 bb 成员
    (bb->cref_from).clear();
    (bb->cref_to).clear();

    // 如果存在对应的 future label，则删除之 
    if(future_label.count(start)) 
    {
	future_label.erase(start);
    }// end of if( )
  
    curr = start;
   
    // 确定出当前基本块的全部指令 
    while(true) // 搜索当前 bb 的边界
    {
        if(!ua_ana0(curr)) 
	{
	    msg( "ending ! prev = 0x%lx -- curr = 0x%lx", 
		 prev,
		 curr
	       );
	    goto __Exit; //output->cmd
	}// end of if()		

        memset(&pcode, 0, sizeof(pcode));
        pcode.eip = (uint64_t)curr; // 保存机器码地址
        (bb->codes).push_back(pcode);

        next = get_item_end(curr);

        //if(is_basic_block_end(true))        
 
		
	if(is_basic_block_end(false)) // the parameter is 'call_insn_stops_block' !
	{
	    bb_num = bb_num + 1;
	    break; //bbœáÊø?
	}// end of if( )
	
	prev = curr;
        curr = next;
    }// end of while{true}


    bb->first = start;         // bb.first = 入口代码地址
    exit2entry[curr] = start;  // 保存 exit->entry 映射（实质为记录出口边的关系）

    // 分析交叉参考
    xrefblk_t xb;

    // IDA SDK: 
    // The following functions return: 1-ok, 0-no (more) xrefs
    // They first return code references, then data references. <<<< 首先返回代码参考
    // If you need only code references, you need to check 'iscode' after each call.
    // If you need only data references, use XREF_DATA bit.
  
    // “参考”（引用）当前 bb 的 bb
    // cref_from = 参考当前 bb 的出口地址。注意：这里对应的 bb 可能还未生成

	
    // xb.first_to: 计算以 start 为目标的所有的 “源头” 中的第一个, 并将它设置到 xb.from 上
    if( xb.first_to( start, 
	             XREF_ALL
		   ) && xb.iscode
      )
    {
        (bb->cref_from).push_back(xb.from);
        while(xb.next_to() && xb.iscode) 
	{
	    (bb->cref_from).push_back(xb.from);
	}// end of while{ }
    }// end of if( )

    // 被当前 bb 所参考的地址
    next_entry = 0;

    ////////////////////////////////////////////////////////////////////////////
    //  bb 的 cref_to 最多包含 2 个分支：
    //  1. size = 0，无分支（如 jmp esi, ret）
    //  2. size = 1，1个分支（如 jmp, ordinary flow）。这时使用 cref_to[0]
    //  3. size = 2，2个分支（jcc），约定 ordinary flow=cref_to[0], dst=cref_to[1]
    //
    ////////////////////////////////////////////////////////////////////////////
  
    if ( !( xb.first_from( (bb->codes).back().eip, 
		           XREF_ALL
			 ) && xb.iscode
 	  ) 
       )
    {
	/*
	mysqldump.Mysql_DumpBasicBlockInfo( entry,
					    bb.first, 
					    bb.codes.back( ).eip,
					    0,
					    0
					);
	*/
        goto __SaveBasicBlock; // 无 cref,next_entry=0
    }
    else
    {
	// 一条指令最多存在 2 个代码分支。IDA 先返回代码参考。所以下面至多只需调用一次 next_from　获取另一个分支的信息
	uint64_t first_to   = xb.to;
        uchar    first_type = xb.type;

        if(xb.next_from() && xb.iscode) // 存在第 2 个分支？
        {
            uint64_t second_to = xb.to;

      	    if(first_type == flow_ordinary)
      	    {
		next_entry = first_to; // 继续分析 ordinary flow
				
		(bb->cref_to).push_back(first_to);  //cref_to[0] = ordinary-flow
		(bb->cref_to).push_back(second_to); //cref_to[1] = dst

		// 在 future_label 插入 jcc 的 dst。在之后的轮次再分析。这里先分析 ordinary-flow
		if ( !path_mark.count(second_to) &&  // 之前未分析过
       		     !future_label.count(second_to)
		   )
        	{
		    future_label.insert(second_to);
		}
      	    }
      	    else
            {
		next_entry = second_to;

		(bb->cref_to).push_back(second_to); //cref_to[0] = ordinary flow
		(bb->cref_to).push_back(first_to);  //cref_to[1] = dst


		// 在 future_label 插入 first_to 留待之后的轮次分析

		if( !path_mark.count(first_to) && 
		    !future_label.count(first_to)
		  )           
		{
		    future_label.insert(first_to);
		}
	    }// end of if(first_type)

	    /*
	    mysqldump.Mysql_DumpBasicBlockInfo( entry,
						bb.first, 
						bb.codes.back().eip,
						first_to,
						second_to
					      );
	    */
        }
        else // 只有一个分支
        {
            (bb->cref_to).push_back(first_to);
      	    next_entry = first_to;

	    /*
	    mysqldump.Mysql_DumpBasicBlockInfo( entry,
						bb.first, 
						bb.codes.back().eip,
						first_to,
						0
					      );
	    */
        }// end of if(xb.next_from() && xb.iscode)
    }// end of if(!(xb.first_from())

__SaveBasicBlock:
    bbs[start] = bb;
    start = next_entry;

    if (start == 0) // 已经到了叶子节点
    {
	goto __FutureLabel;
    }// end of if()

    if (path_mark.count(start))
    {
        goto __FutureLabel; // 已经处理过这个节点。直接去找下一个处理
    }// end of if()

    goto __Analysis; // 分析下一个 bb

__FutureLabel:
    if (future_label.empty()) // 工作集为空了，结束分析
    {
	goto __Exit;
    }
    else
    {  
	// 取第一项
        start = *future_label.begin(); 
        goto __Analysis;
    }// end of if()

__Exit:
    hide_wait_box();    
    
}// end of gather_ida_basic_blocks()


BasicBlock * CFuncBBManager::generate_cfg_bb( Cfg         * cfg,
				              CBasicBlock * bblock,
				              bool          isEntry
				            )
{
    BasicBlock * bb = cfg->addBasicBlock(bblock->first); 

    addr_t  insn_addr = 0;
    char    insn_buf[1024];
    ssize_t insn_size = 0;

    Instruction * insn = NULL;

    if (isEntry)
    {
	cfg->setEntry(bb);
    }

    // 将本 bb 的所有指令添加进来
    for ( std::vector<PCode>::iterator insn_iter = (bblock->codes).begin();
	  insn_iter != (bblock->codes).end();
	  insn_iter ++
	)
    {
	insn_addr = (addr_t)((*insn_iter).eip);
	insn_size = get_item_size(insn_addr);

	get_many_bytes( insn_addr, 
		        insn_buf, 
			insn_size
		      );

	insn = new Instruction(insn_addr, insn_buf, insn_size);
    	bb->addInstruction(insn);
    }

    // 根据本 bb 的最后一条指令是否为 ret，判定当前基本块是否是函数的 exit-bb
    // HHui NOTE: 这里本来可以直接比对 x86 平台 ret 指令的字节码。此处基于中间语言的判定，旨在让代码适应更多的目标平台
    insn->decode();
    if (insn->isReturn())
    {
	(cfg->exits).insert(bb);
    }
    
    return bb;
}


void CFuncBBManager::generate_all_bbs( Cfg * cfg,
				       uint64_t  func_entry
				     )
{
    std::queue<uint64_t> workset;
    std::set<uint64_t>   analyzed_set;

    BasicBlock * outbb = NULL;

    workset.push(func_entry);

    while (!workset.empty())
    {
	uint64_t addr = workset.front(); 
	workset.pop();

	CBasicBlock * bblock = bbs[addr];

	if (func_entry == addr)
	{
	    outbb = generate_cfg_bb(cfg, bblock, true);
	}
	else
	{
	    outbb = generate_cfg_bb(cfg, bblock, false);
	}

	analyzed_set.insert(addr);
	gen_bbs[addr] = outbb; 

	// 将后继基本块们添加到工作集中
	for ( vector<uint64_t>::iterator iter = (bblock->cref_to).begin();
	      iter != (bblock->cref_to).end();
	      iter ++
	    )
	{
	    if (analyzed_set.count(*iter) == 0)
	    {
	       	workset.push(*iter);
	    }
	}
    }
}


void CFuncBBManager::generate_bb_links( Cfg * cfg,
					uint64_t  func_entry
				      )
{
    std::queue<uint64_t> workset;
    std::set<uint64_t>   analyzed_set;

    workset.push(func_entry);

    BasicBlock * srcbb = NULL;
    BasicBlock * dstbb = NULL;

    while (!workset.empty())
    {
	uint64_t addr = workset.front(); 
	workset.pop();

	CBasicBlock * bblock = bbs[addr];
	srcbb = gen_bbs[addr];

	// 在当前 bb 和其后继 bb 之间建立边
	for ( vector<uint64_t>::iterator iter = (bblock->cref_to).begin();
	      iter != (bblock->cref_to).end();
	      iter ++
	    )
	{
	    if (analyzed_set.count(*iter) == 0)
	    {
		workset.push(*iter);
	    }

	    dstbb = gen_bbs[*iter];
	    cfg->linkBasicBlocks(srcbb, dstbb);
	}

	analyzed_set.insert(addr);
    }
}


void CFuncBBManager::generate_cfg(Cfg * cfg, uint64_t func_entry)
{
    generate_all_bbs( cfg,
		      func_entry
		    );

    generate_bb_links( cfg,
		       func_entry
		     );
}
