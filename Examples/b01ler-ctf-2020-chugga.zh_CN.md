此处为题目的二进制文件
https://github.com/b01lers/b01lers-ctf-2020/tree/master/rev/100_chugga_chugga

![image](https://github.com/user-attachments/assets/48c2bab3-92fa-4860-80e7-77ad25e4a718)

直接分析主函数main_main
函数通过 `fmt_Fprintln` 和 `fmt_Fscan` 操作标准输入输出流，提示用户输入数据并解析输入内容。

![image](https://github.com/user-attachments/assets/1cc711bd-7af1-4427-8e5a-f77d2c4823a2)
![image](https://github.com/user-attachments/assets/b7b68c0e-33a2-486c-871a-6d51d52d06e4)

 `fmt_Fprintln` 和 `fmt_Fscan`函数不能被angr直接替换，因此选择以地址`0x493047`作为angr模拟运行的入口点，使用探索技术，`find`参数为`0x49327E`，`avoid`参数为`0x493066`

脚本代码：
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

运行时通过该工具可以判断：程序在运行时进入了`runtime_panicindex`函数，产生大量`active`状态，这是go语言的运行时错误处理函数，与程序核心逻辑无关，将该地址加入avoid列表


脚本代码：
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


成功找到满足`found`的`state`

观察具体的符号变量约束，出现了`mem_7ffffffffff0048`(angr进入空状态时rsp指向的默认位置)与`mem_ffffffffffffffxx`()，采取符号变量具体化策略：

![image](https://github.com/user-attachments/assets/488d7f23-c547-439c-8189-3b7610164b4a)

使用IDA分析确定用户输入保存的地址

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

使用该工具观察到运行过程中的符号约束名称为手动插入的flag符号变量，证明生成约束有效，成功求解












