#ifndef __SERIALIZE_H__
#define __SERIALIZE_H__

#include "cfg.h"
#include "callgraph.h"
#include "func.h"
#include "prog.h"
#include <map>

#include <inttypes.h>

// #include <pin.H>
typedef uint64_t ADDRINT;

void unserialize( const char *, 
		  Prog &, 
		  CallGraph * &, 
		  std::map<ADDRINT, Function *> &
		);

void serialize(const char *, const Prog &);

#endif // !__SERIALIZE_H__

// Local Variables: 
// c-basic-offset: 4
// compile-command: "dchroot -c typeinfer -d make"
// End:
