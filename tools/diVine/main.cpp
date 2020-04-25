#include <stdio.h>
#include <string>
#include "argv_readparam.h"

#include "IRRecoveryManager.h"

/*
cl::opt<std::string> fn_exe("exe", cl::desc("executable file path"), cl::Required);
cl::opt<std::string> fn_cfginfo("cfginfo", cl::desc("CFG info file"), cl::Required);
cl::opt<std::string> fn_bbinfo("bbinfo", cl::desc("BB info file"), cl::Required);
*/


int    DEBUG_LEVEL = 0;
FILE * DEBUG_FILE  = NULL;


std::string fn_exe;
std::string fn_bbinfo;
std::string fn_cfginfo;
std::string dot;


static void parse_arguments(int argc, char * argv[])
{
    char * tmpstr = NULL;
    int    tmpint = 0;

    if((tmpstr = argv_getString(argc, argv, "--dot=", NULL)) != NULL ) 
    {
	dot = tmpstr;
    } 
    else 
    {
	dot = "";
    }

    if((tmpstr = argv_getString(argc, argv, "--exe=", NULL)) != NULL ) 
    {
	fn_exe = tmpstr;
    } 
    else 
    {
	printf("param '--exe' is required !\n");
	exit(0);
    }

    if((tmpstr = argv_getString(argc, argv, "--bbinfo=", NULL)) != NULL ) 
    {
	fn_bbinfo = tmpstr;
    } 
    else 
    {
	printf("param '--exe' is required !\n");
	exit(0);
    }

    if((tmpstr = argv_getString(argc, argv, "--cfginfo=", NULL)) != NULL ) 
    {
	fn_cfginfo = tmpstr;
    } 
    else 
    {
	printf("param '--exe' is required !\n");
	exit(0);
    }
}


int main(int argc, char * argv[])
{
    parse_arguments(argc, argv);

    IRRecoveryManager * irm = new IRRecoveryManager( fn_exe,
	    	       				     fn_bbinfo,
	    	       				     fn_cfginfo,
						     dot
	    	     				   );
    if (!irm->init())
    {
	printf("IRRecoveryManager init() fails !\n");
	delete irm;
    }

    irm->generate_divine_cfgs();

    irm->print_graph_divine_cfgs();

    return 0;
}
