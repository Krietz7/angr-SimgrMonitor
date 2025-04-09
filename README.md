## angr-SimgrMonitor

[中文](README.zh_CN.md)

A non-intrusive monitoring tool for angr framework, designed to track the execution status of `SimulationManager` in real-time. Integrated via decorator pattern, it requires no code modification to collect critical runtime metrics, with real-time visualization powered by `rich` library.

This tool is designed to help users detect common symbolic execution risks early and identify optimization solutions through real-time monitoring, including:
- Path Explosion
- Complex external Call
- Perform path optimization
- Symbol variable concrete
 
### Key Features
- Real-time Timing: Millisecond-precise execution time tracking

- Memory Analysis: Process memory usage monitoring

- State Statistics: State counts categorized by stash types (`active`/`found`/`avoid` etc.)

- Focus Blocks Analysis: Track most frequently executed basic blocks

- Callstack Profiling: Statistics the distribution of different callstack states

- Symbol variable statistics: statistics and analyze the constraint complexity of different symbol variables

### Dependencies
- Python version >= 3.10
- `angr` version >= 9.0
- `aspectlib` module
- `psutil` module
- `rich` module

### Installation
```bash
# Clone repository
git clone https://github.com/Krietz7/angr-SimgrMonitor
cd angr-SimgrMonitor

# Install (auto-handles dependencies)
pip install .
```

In addition, you can also copy "angr_simgr_monitor.py" file to the current directory or add it's path to environment variable "PYTHONPATH" to use the tool

### Quick Start


```python
import angr
from angr_simgr_monitor import monitored_simgr

# Initialize angr project
proj = angr.Project("target_binary", auto_load_libs=False)
init_state = proj.factory.entry_state()

# Create SimulationManager with monitoring
sm = proj.factory.simulation_manager(init_state)
with monitored_simgr():  # <-- Core decorator
    sm.run()             # Supports run()/step()/explore() methods
```

### ScreenShot
![image](https://github.com/user-attachments/assets/091f2363-671a-46ba-bddd-fab4be9d3722)

for more infomation, see: [Examples](./Examples)



### Advanced Configuration
```python
# Monitor refresh frequency per second. To reduce the performance impact of this tool, please try to lower the configuration item
REFRESH_TIME_PER_SECOND = (int)

# Enable millisecond precision
TIMER_ACCURATE_TO_MILLISECONDS = (bool)  

# Number of foucs blocks to display
BLOCK_EXECUTION_COUNTS_DISPLAY = (int) 

# Number of callstack types to show
CALLSTACK_COUNTS_DISPLAY = (int)
```
