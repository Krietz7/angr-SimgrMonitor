## angr-SimgrMonitor
这是一个专为 angr 框架设计的非侵入式监控工具，可实时追踪 SimulationManager 的执行状态。通过装饰器模式集成，无需修改原有代码即可获取关键运行时指标，并通过 `rich` 库输出实时监控界面。

该工具旨在通过实时监控来帮助用户尽早发现常见的符号执行问题并确定优化方案，包括：
- 路径爆炸
- 复杂的外部调用
- 执行路径优化
- 符号变量具体化

### 主要功能
- 实时时间监控：精确到毫秒的执行时间统计

- 内存占用分析：显示进程内存使用量变化

- 状态分类统计：按 stash 类型（active/found/avoided 等）统计 states 数量

- 聚焦代码分析：追踪执行次数最多的基本块（Basic Block）

- 调用栈分析：统计不同调用栈状态的分布情况

- 符号变量统计：统计并分析不同符号变量的约束复杂度

### 依赖
- Python 版本 >= 3.10
- `angr` 版本 >= 9.0
- `aspectlib` 模块
- `psutil` 模块
- `rich` 模块

### 安装

```bash
# 克隆仓库
git clone https://github.com/Krietz7/angr-SimgrMonitor
cd angr-SimgrMonitor

# 安装（自动处理依赖）
pip install .
```

除此之外，您也可以将"angr_simgr_monitor.py"文件复制到当前目录或将其路径添加到环境变量"PYTHONPATH"中以使用该工具


### 快速开始

```python
import angr
from angr_simgr_monitor import monitored_simgr

# 初始化并创建状态
proj = angr.Project("target_binary", auto_load_libs=False)
init_state = proj.factory.entry_state()

# 创建模拟执行管理器并启动监控
sm = proj.factory.simulation_manager(init_state)
with monitored_simgr():  # <-- 核心装饰器
    sm.run()             # 支持 run()/step()/explore() 等方法
```

### 进阶配置
```python
# 监控每秒刷新频率，若要降低该工具对性能影响，请尽量调低该配置项
REFRESH_TIME_PER_SECOND = (int)

# 是否启用毫秒时间统计精度
TIMER_ACCURATE_TO_MILLISECONDS = (bool)

# 显示聚集代码数量
BLOCK_EXECUTION_COUNTS_DISPLAY = (int)

# 显示调用栈类型数量
CALLSTACK_COUNTS_DISPLAY = (int)
```

