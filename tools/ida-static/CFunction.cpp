#include "ida.hpp"
#include "idp.hpp"
#include "loader.hpp"
#include "funcs.hpp"

#include "ida_plugin.h"
#include "CBasicBlock.h"

#include "cfg.h"


void FunctionAnalysis( )
{
    char funcName[1024];
    func_t * curFunc = NULL;    
 
    // functions' enumeration      
    for (int f = 0; f < get_func_qty(); f++)
    {
        curFunc = getn_func(f);
             	
     	get_func_name( curFunc->startEA,
        	       funcName,
                       sizeof(funcName)-1
		     );
        msg( "%s:\t%a\n", 
	     funcName, 
	     curFunc->startEA
	   );

	gather_basic_block(curFunc->startEA);

    }// end of for{ }
}// end of FunctionAnalysis( )		
