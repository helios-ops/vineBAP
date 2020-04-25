#include <cstddef>

using namespace std;

#include "callgraph.h"

void CallGraph::addCall(Function *caller, Function *callee) {
    CallGraphEdge *e;

    if (!hasVertex(caller)) {
	addVertex(caller);
    }

    if (!hasVertex(callee)) {
	addVertex(callee);
    }

    e = new CallGraphEdge(caller, callee);
    assert(e);

    addEdge(caller, callee, e);

    if (!main)
	setMain(caller);
}

std::string CallGraph::dot() {
    std::string r = "";
    char tmp[1024];

    r = "digraph G {\n";

    for ( CallGraph::const_func_iterator fit = func_begin(); 
	  fit != func_end(); 
	  fit++
	) 
    {
	Function *f1 = *fit;
	sprintf( tmp, 
		 "func_%lx [label=\"%s@%lx\\n[%s]\", shape=rectangle%s"
		 ",URL=\"%lx.svg\"];\n", 
		 f1->getAddress(), 
		 f1->getName(), 
		 f1->getAddress(), 
		 f1->getModule(), f1 != main ? "" : ", color=red",
		 f1->getAddress()
	       );
	r += "   " + std::string(tmp);
    }

    for ( CallGraph::const_edge_iterator eit = edge_begin();
	  eit != edge_end(); 
	  eit++
	) 
    {
	Function *f1 = (*eit)->getSource();
	Function *f2 = (*eit)->getTarget();

	sprintf( tmp, 
		 "func_%lx -> func_%lx;\n", 
		 f1->getAddress(), 
		 f2->getAddress()
	       );
	r += "   " + std::string(tmp);
    }

    r += "}";

    return r;
}

std::string CallGraph::vcg() {
    std::string r = "";
    char tmp[1024];

    r = "graph: {\n";

    for (CallGraph::const_func_iterator fit = func_begin(); 
	 fit != func_end(); fit++) {
	Function *f1 = *fit;
	sprintf(tmp, "node: { title: \"func_%lx\" "
		"label: \"%s@%lx\\n[%s]\" }\n", 
		f1->getAddress(), f1->getName(), f1->getAddress(), 
		f1->getModule());
	r += "   " + std::string(tmp);
    }

    for (CallGraph::const_edge_iterator eit = edge_begin();
	 eit != edge_end(); eit++) {
	Function *f1 = (*eit)->getSource();
	Function *f2 = (*eit)->getTarget();
	    sprintf(tmp, "edge: { sourcename: \"func_%lx\" "
		    "targetname: \"func_%lx\"}\n", f1->getAddress(), 
		    f2->getAddress());
	    r += "   " + std::string(tmp);
    }

    r += "}";

    return r;
}


// Local Variables: 
// c-basic-offset: 4
// compile-command: "dchroot -c typeinfer -d make"
// End:
