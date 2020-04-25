#include "debug.h"
#include "types.h"
#include "PinDisasm.h"
// #include <pin.H>
#include <string.h>

extern "C"{
#include <xed-interface.h>
}

size_t inslen(ADDRINT addr) {
    xed_state_t dstate;
    xed_decoded_inst_t xedd;

    xed_tables_init();

    xed_state_zero(&dstate);
    xed_state_init( &dstate,
                    XED_MACHINE_MODE_LEGACY_32, 
                    XED_ADDRESS_WIDTH_32b, 
                    XED_ADDRESS_WIDTH_32b
		  );

    xed_decoded_inst_zero_set_mode(&xedd, &dstate);
    xed_decode(&xedd, (const xed_uint8_t*) addr, 16);
    return xed_decoded_inst_get_length(&xedd);
}


// Resolve thunks (only for main executable) In order for this to work lazy
// binding must be disabled (i.e., LD_BIND_NOW must be set)
// if (isplt(funcaddr) && !islib(instrptr)) {
ADDRINT derefplt(ADDRINT instrptr, ADDRINT funcaddr, ADDRINT ebx) 
{
    /* 之于动态链接：
     * .got 节是一个维护着所有函数地址表。这个表里面的各个函数地址是由动态链接器填充的。这里使用 LD_BIND_NOW 让动态链接器在程序加载到内存后
     *      立即填充；
     * .plt 节为 .got 节中的每个条目维护着一个跳转 stub。这里期待着 plt 节的内容如下： 
     *      jmp *0x804a014 或 jmp [0xc + ebx]    （这里的期待应该对应于较老的 Linux 系统！ ubuntu-18.04 目前为不适用！）
     *
     * 当我们的 pintracer.so 到达这里后，EBX 指向 .plt 节中该条目的起始位置。下面代码对被调用函数地址的获取正是基于这个前提。
     * */
    unsigned char *plt = (unsigned char *) funcaddr;
  
    debug2("Try to dereference PLT entry @ %lx with base %lx\n", funcaddr, ebx);

    // The entry is of the form 'jmp *0x804a014'
    if (plt[0] == 0xFF && plt[1] == 0x25) 
    {
      	funcaddr += 2;
	// funcaddr = *((ADDRINT *) (*((ADDRINT *) funcaddr)));
	
	// get the operand
	funcaddr = *((UINT32 *)funcaddr);
	
	// make the relocation
	funcaddr = (ADDRINT)plt + 6 + funcaddr;
	
	// get the addr
	funcaddr = *((ADDRINT *)funcaddr);

	debug2( "Resolved function address %lx (PLT) -> %lx\n", 
	  	(ADDRINT) plt,
	    	funcaddr
	      );
    } 
    else if (plt[0] == 0xFF && plt[1] == 0xa3) 
    {
      	// The entry is of the form 'jmp *0xc(%ebx)' 
	funcaddr += 2;
	funcaddr = *((ADDRINT *) funcaddr);
	funcaddr = *((ADDRINT *) (ebx + funcaddr));
	debug2( "Resolved PIC function address %lx (PLT) -> %lx\n", 
	  	(ADDRINT) plt,
	    	funcaddr
	      );
    } 
  
    else 
  
    {
    
      	assert_msg( 0, "Unknown PLT entry type eip:%lx funcaddr:%lx "
		    "plt[0]:%.2x plt[1]:%.2x", 
	            instrptr, 
	            funcaddr, 
	            plt[0], 
	            plt[1]
	          );
    }
 
    return funcaddr;
}

byte_t ispicthunk(ADDRINT instptr) {
  if (memcmp((byte_t *) instptr, "\x8b\x1c\x24\xc3", 4) == 0) {
    return '\x1c';
  } else if (memcmp((byte_t *) instptr, "\x8b\x0c\x24\xc3", 4) == 0) {
    return '\x0c';
  } else if (memcmp((byte_t *) instptr, "\x8b\x14\x24\xc3", 4) == 0) {
    return '\x14';
  }
  
  return 0;
}

bool patchpicthunk(ADDRINT instrptr, ADDRINT funcaddr, Instruction *I) {
  byte_t r = ispicthunk(funcaddr);
  // Is the target 'mov (%esp),%ebx; ret'?
  if (r) {
    // Simulate a 'mov retaddr, %ebx;'
    debug2("Detected PIC thunk @ %lx, called from %lx\n", funcaddr, 
	   instrptr);
    ADDRINT addr = instrptr + 5;
    byte_t fake[5];

    // Generate fake 'mov $nexteip,%ebx'
    fake[0] = r;
    memcpy(fake + 1, &addr, sizeof(addr));
    I->setRawBytes(fake, 5);
    
    return true;
  }

  return false;
}

// Local Variables: 
// mode: c++
// c-basic-offset: 4
// compile-command: "dchroot -c typeinfer -d make"
// End:
