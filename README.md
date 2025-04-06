## angr-SimgrMonitor
A non-intrusive monitoring tool for angr framework, designed to track the execution status of `SimulationManager` in real-time. Integrated via decorator pattern, it requires no code modification to collect critical runtime metrics, with real-time visualization powered by rich library.

This tool is designed to help users detect common symbolic execution risks early through real-time monitoring, including:
- Path Explosion
- Complex external Call
- Execution Optimization

### Key Features
- Real-time Timing: Millisecond-precise execution time tracking

- Memory Analysis: Process memory usage monitoring

- State Statistics: State counts categorized by stash types (`active`/`found`/`avoid` etc.)

- Focus Blocks Analysis: Track most frequently executed basic blocks

- Callstack Profiling: Statistics the distribution of different callstack states

### Dependencies
- `aspectlib` module
- `rich` module

### Quick Start
To use this script, you should copy "angr_simgr_monitor.py" file to the current directory or add it's path to environment variable "PYTHONPATH"

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


### Advanced Configuration
```python
REFRESH_TIME_PER_SECOND = (int)           # Refresh interval (ms)
TIMER_ACCURATE_TO_MILLISECONDS = (bool)   # Enable millisecond precision
BLOCK_EXECUTION_COUNTS_DISPLAY = (int)    # Number of foucs blocks to display
CALLSTACK_COUNTS_DISPLAY = (int)          # Number of callstack types to show
```
