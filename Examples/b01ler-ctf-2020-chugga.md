The challenge binary from here:
https://github.com/b01lers/b01lers-ctf-2020/tree/master/rev/100_chugga_chugga

![image](https://github.com/user-attachments/assets/48c2bab3-92fa-4860-80e7-77ad25e4a718)

Directly analyze the main function `main_main`
The function operates the standard input and output stream through `fmt_Fprintln` and `fmt_Fscan`, prompting the user to enter data and parse the input content.

![image](https://github.com/user-attachments/assets/1cc711bd-7af1-4427-8e5a-f77d2c4823a2)
![image](https://github.com/user-attachments/assets/b7b68c0e-33a2-486c-871a-6d51d52d06e4)

The `fmt_Fprintln` and `fmt_Fscan` functions cannot be replaced directly by angr.
So the address `0x493047` is selected as the entry point for the angr simulation operation. 
Using the exploration technology, the `find` parameter is `0x49327E` and the `avoid` parameter is `0x493066`

Script code:
```python
import angr
from angr_simgr_monitor import *

proj = angr.Project('./chugga', load_options={"auto_load_libs": False}, main_opts={'base_addr': 0x400000})
init_state = proj.factory.blank_state(addr = 0x493047)

sm = proj.factory.simulation_manager(init_state)
with monitored_simgr(): 
    sm.explore(find=0x49327E,avoid=0x493066)
```
![image](https://github.com/user-attachments/assets/2299fc7c-39b9-410d-914e-e1e912066934)
![image](https://github.com/user-attachments/assets/071a6061-ae01-4d36-9b23-56675318d198)

This tool can be used to judge at runtime: the program enters the `runtime_panicindex` function at runtime, generating a large number of `active` states. 
This is the runtime error handling function of the Go language, which has nothing to do with the program's core logic. Add this address to the avoid list.



Script code:
```python
import angr
from angr_simgr_monitor import *

proj = angr.Project('./chugga', load_options={"auto_load_libs": False}, main_opts={'base_addr': 0x400000})
init_state = proj.factory.blank_state(addr = 0x493047)

sm = proj.factory.simulation_manager(init_state)
with monitored_simgr(): 
    sm.explore(find=0x49327E,avoid=[0x493066,0x49328D])
```
![recording](https://github.com/user-attachments/assets/9530ca4e-1e41-4f4e-976b-3bb76897bbca)


Successfully found a `state` satisfying `found`
Observing the specific symbol variable constraints, including `mem_7ffffffffff0048` (the default position pointed to by rsp when angr enters the empty state) 
and `mem_ffffffffffffxx`(), and the symbol variable concrete strategy is adopted:

![image](https://github.com/user-attachments/assets/488d7f23-c547-439c-8189-3b7610164b4a)

Use IDA analysis to determine the user input saved address
```python
import angr
from angr_simgr_monitor import *

proj = angr.Project('./chugga', load_options={"auto_load_libs": False}, main_opts={'base_addr': 0x400000})
init_state = proj.factory.blank_state(addr = 0x493047)

rsp = init_state.regs.rsp
flag_struct_pointer_addr = rsp + 0xa8 - 0x60
flag_struct_addr = 0x300000
flag_addr = 0x200000
flag_length = 23
flag_length_addr = flag_struct_addr + 8
init_state.memory.store(flag_struct_pointer_addr,flag_struct_addr.to_bytes(8, byteorder='little'))
init_state.memory.store(flag_struct_addr,flag_addr.to_bytes(8, byteorder='little'))
init_state.memory.store(flag_length_addr,flag_length.to_bytes(8, byteorder='little'))
flag_chars = [claripy.BVS('flag', 8) for _ in range(flag_length)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])
init_state.memory.store(flag_addr,flag)


sm = proj.factory.simulation_manager(init_state)
with monitored_simgr(): 
    sm.explore(find=0x49327E,avoid=[0x493066,0x49328D])

if sm.found:
    f = sm.found[0]
    flag = f.memory.load(flag_addr, flag_length)
    print(f.solver.eval_upto(flag,n=10,cast_to=bytes))
```

![recording 1](https://github.com/user-attachments/assets/d6e24208-8339-46dd-9b82-bf8cab3a870d)

Use this tool to observe that the symbol constraint name during the run is a flag symbol variable inserted manually, proving that the generation constraint is valid and the solution is successfully













