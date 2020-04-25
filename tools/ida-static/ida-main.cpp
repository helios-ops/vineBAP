/* hhui NOTE:　我们这里编译的插件是 32 位程序（IDA-6.4 的插件要求），所以我们使用 -m32 编译选项。然而该选项的应用将导致 IDA 本身 SDK 
 *             在引用 64 位宿主机器 C++ cstdlib 时出错。以下的这些宏，就是为了避免上述问题而定义的！
 *
 */
// #include <cstdint>
// #include <cstddef>
// #include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
#ifndef SWIG
#define SWIG
#endif

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
*/

#ifndef USE_STANDARD_FILE_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#endif


#ifdef _GLIBCXX_USE_INT128
#undef _GLIBCXX_USE_INT128
#endif


#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <funcs.hpp>
#include <area.hpp>

#include "cfg.h"
//#include "callgraph.h"
//#include "prog.h"

#include "H_pcode.h"
#include "CFGRecovery.h"


/* ------------------------------------------------------------ */
// Map addresses to functions
static std::map <uint64_t, Function *> functions;
// static CallGraph * callgraph = NULL;
// static Prog prog;
/* ------------------------------------------------------------ */


int IDAP_init(void)
{
    //在这里做一些校验，以确保您的插件是被用在合适的环境里。
    return PLUGIN_OK;
}


void IDAP_term(void)
{

    //当结束插件时，一般您可以在此添加一点任务清理的代码。
    return;
}


// 插件可以从plugins.cfg文件中，被传进一个整型参数。
// 当按下不同的热键或者菜单时，您需要一个插件做不同
// 的事情时，这非常有用。
void IDAP_run(int arg)
{

    // 插件的实体 

    msg("Hello world!");

    int funcNum = get_func_qty();

    for (int i = 0; i < funcNum; i++) 
    {
	func_t * curFunc = getn_func(i);
	msg("Function at: %a\n", curFunc->startEA);

	Function * myfunc = new Function(curFunc->startEA);
	CFuncBBManager * func_manager = new CFuncBBManager();
    	func_manager->generate_cfg( myfunc->getCfg(), 
				    curFunc->startEA
				  );

    }
}


// 这些不太重要，但我还是设置了。
char IDAP_comment[] = "This is my test plug-in";

char IDAP_help[] = "My plugin";

// 在Edit->Plugins 菜单中，插件的现实名称。它能被用户的plugins.cfg文件改写
char IDAP_name[] = "ida-static";

// 启动插件的热键
char IDAP_hotkey[] = "Alt-X";



// 所有PLUGIN对象导出的重要属性。
plugin_t PLUGIN =
{

    IDP_INTERFACE_VERSION, // IDA version plug-in is written for
    0, 			   // Flags (see below)

    IDAP_init, 		   // Initialisation function
    IDAP_term, 		   // Clean-up function
    IDAP_run, 		   // Main plug-in body
    IDAP_comment,	   // Comment – unused
    IDAP_help, 		   // As above – unused
    IDAP_name,		   // Plug-in name shown in

    // Edit->Plugins menu
    IDAP_hotkey		   // Hot key to run the plug-in
}; 
