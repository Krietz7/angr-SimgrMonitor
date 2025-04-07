# angr_decorator.py
import angr
import claripy
import logging

import time
import threading
from os import getpid
from psutil import Process
from collections import Counter


import rich
from queue import Queue, Empty
import aspectlib



'''
This decorator measures the execution status of angr.simulation_manager methods (run, step, and explore).
It provides real-time monitoring through a timer thread and displays execution statistics, including block
execution frequency and callstack distribution.

Parameters:
- REFRESH_TIME_PER_SECOND: The number of times the monitoring is updated in one second.
- TIMER_ACCURATE_TO_MILLISECONDS: If True, the timer will display milliseconds; otherwise, it will only show seconds.
- BLOCK_EXECUTION_COUNTS_DISPLAY: The number of most frequently executed blocks to display.
- CALLSTACK_COUNTS_DISPLAY: The number of most frequent callstacks to display.
'''

# config
REFRESH_TIME_PER_SECOND = 50
TIMER_ACCURATE_TO_MILLISECONDS = True
BLOCK_EXECUTION_COUNTS_DISPLAY = 10
CALLSTACK_COUNTS_DISPLAY = 10


class SimgrTimer:
    def __init__(self):
        self.start_time = time.time()
        self.is_stopped = threading.Event()
        self.queue = Queue()
        self.update_interval = 1 / REFRESH_TIME_PER_SECOND
        self.thread = threading.Thread(target=self._run)
        self.thread.start()

    def _run(self):
        while not self.is_stopped.is_set():
            elapsed = time.time() - self.start_time

            hours, rem = divmod(elapsed, 3600)
            minutes, seconds = divmod(rem, 60)
            milliseconds = int((seconds - int(seconds)) * 1000)

            if TIMER_ACCURATE_TO_MILLISECONDS:
                time_str = (
                    f"{int(hours):02d}:{int(minutes):02d}:"
                    f"{int(seconds):02d}.{milliseconds:03d}"
                )
            else:
                time_str = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"

            self._flush_queue()
            self.queue.put(time_str)
            time.sleep(self.update_interval)

    def _flush_queue(self):
        while True:
            try:
                self.queue.get_nowait()
            except Empty:
                break

    def stop(self):
        self.is_stopped.set()
        self.thread.join()


class SimgrCLI():
    def __new__(cls):
        if not hasattr(cls, "_instance"):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self.timer = SimgrTimer()
        self.simgr_info = SimgrInfo().get_instance()

        self.is_stopped = threading.Event()

        self.display_thread = threading.Thread(target=self._run_display)
        self.display_thread.start()


    def _get_display_assemble(self):
        try:
            time_str = self.timer.queue.get(timeout=0.01)
        except Empty:
            return None

        # Display Basic Information
        display_content = [("[Timer] ", "bold cyan"),(time_str, "bold green"),
                (" | [Memory usage] ", "bold cyan"),(self.simgr_info.memory_usage, "bold red"),
                ("\n[Sim manager stash] ", "bold cyan"),(self.simgr_info.simgr_text, "bold yellow")]

        # Display Blocks Execution Statistics
        execution_count_statistics,execution_count_top = self.simgr_info.retrieve_block_execution_statistics()
        display_content.append(("\n-----------------------[Blocks Execution Statistics]----------------------------\n", "bold cyan"))
        display_content += (("Total execution times: ", "bold magenta"),(str(execution_count_statistics),"bold magenta"),"\n")

        for address_describtion,value in execution_count_top:
            display_content += [address_describtion, " : ", str(value), str("\n")]
        for _ in range(BLOCK_EXECUTION_COUNTS_DISPLAY - len(execution_count_top)):
            display_content.append("\n")

        display_content.append(("\n--------------------------[Callstack Statistics]--------------------------------\n", "bold cyan")),

        # Display Callstack Statistics
        stash_stack_statistics_top = self.simgr_info.retrieve_states_callstack_statistics()
        for callstack_describiton,value in stash_stack_statistics_top:
            display_content += [callstack_describiton, " : ", str(value), str("\n")]
        for _ in range(CALLSTACK_COUNTS_DISPLAY - len(stash_stack_statistics_top)):
            display_content.append("\n")
        display_content.append(("\n--------------------------------------------------------------------------------\n", "bold cyan"))

        return  tuple(display_content)

    def _run_display(self):
        with rich.live.Live(refresh_per_second=REFRESH_TIME_PER_SECOND) as live:
            while not self.is_stopped.is_set():
                display_content = self._get_display_assemble()
                if display_content == None:
                    continue
                live.update(rich.text.Text.assemble(*display_content))
                self.simgr_info.need_update = False

    def stop(self):
        """ Stop displaying and clean up resources """
        self.is_stopped.set()
        self.timer.stop()

    def __del__(self):
        self.stop()
        self.simgr_info.clear()
        self.display_thread.join()

    @classmethod
    def _set_loggers_level(cls):
        cls.original_loggers_level = logging.getLogger("angr").getEffectiveLevel(), logging.getLogger("claripy").getEffectiveLevel()
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("claripy").setLevel(logging.ERROR)

    @classmethod
    def _restore_loggers_level(cls):
        logging.getLogger("angr").setLevel(cls.original_loggers_level[0])
        logging.getLogger("claripy").setLevel(cls.original_loggers_level[1])


    @classmethod
    def get_instance(cls):
        is_new_instance = False
        if not hasattr(cls, "_instance"):
            cls._instance = cls()
            cls._set_loggers_level()
            is_new_instance = True
        return cls._instance, is_new_instance

    @classmethod
    def del_instance(cls):
        if hasattr(cls, "_instance"):
            while(cls._instance.simgr_info.need_update == True):
                time.sleep(0.1)

            cls._instance.__del__()
            del cls._instance

        cls._restore_loggers_level()


class SimgrInfo():
    def __new__(cls):
        if not hasattr(cls, "_instance"):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self.simgr_text = ""
        self.memory_usage = ""
        self._project = None
        self._target_stash_name = None

        self._block_execult = []
        self._stash_callstack = []


        self.need_update = False

    def get_info_from_args(self, *args, **kwargs):
        self._target_stash_name = kwargs.get("stash", None)
        if self._target_stash_name == None:
            if len(args) > 1 and isinstance(args[1], str):
                self._target_stash_name = args[1]
            else:
                self._target_stash_name = "active"


    def capture_simgr_info(self, simgr: angr.sim_manager.SimulationManager):
        if self._project == None:
            self._project = simgr._project

        self.simgr_text = str(simgr)
        self.memory_usage = self._get_memory_usage()


        self.capture_target_stash_info(simgr)

        self.need_update = True




    def capture_target_stash_info(self, simgr: angr.sim_manager.SimulationManager):
        if self._target_stash_name == None:
            return
        def get_callstack_info(callstack):
            func_descritions = []
            for _, frame in enumerate(callstack):  
                func_addr = frame.func_addr
                if func_addr is None or func_addr == 0:
                    break
                func_descritions.append(self._project.loader.describe_addr(func_addr).split(' in ')[0])

            callstack_description = ""

            for descrition in func_descritions[::-1]:
                if callstack_description != "":
                    callstack_description += " -> "
                callstack_description += descrition
            # if(len(callstack_description) > 80):
            #     callstack_description = "..." + callstack_description[:77].split(' -> ',1)[-1]

            
            return callstack_description


        stashes = simgr.stashes[self._target_stash_name]
        self._stash_callstack.clear()
        for state in stashes:
            callstack_description = get_callstack_info(state.callstack)
            if callstack_description == "":
                self._stash_callstack.append("Empty callstack")
            else:
                self._stash_callstack.append(callstack_description)

        self.need_update = True

    def capture_successor_info(self, stashes):
        for key in stashes.keys():
            for state in stashes[key]:
                self._block_execult.append(state.history.addr)

        self.need_update = True

    def retrieve_block_execution_statistics(self):
        execult_statistics = Counter(self._block_execult)
        execution_count_statistics = execult_statistics.total()
        execution_count_top = []
        for address, count in execult_statistics.most_common(BLOCK_EXECUTION_COUNTS_DISPLAY):
            execution_count_top.append((self._project.loader.describe_addr(address), count))
        return execution_count_statistics,execution_count_top
    
    def retrieve_states_callstack_statistics(self):
        stash_stack_statistics = Counter(self._stash_callstack)
        return stash_stack_statistics.most_common(CALLSTACK_COUNTS_DISPLAY)

    @staticmethod
    def _get_memory_usage():
        process = Process(getpid())
        memory_usage = process.memory_info().vms / float(2 ** 30)
        return '{:.4f}'.format(memory_usage) + " GB"

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, "_instance"):
            cls._instance = cls()
        return cls._instance

    def clear(self):
        self.__init__()

@aspectlib.Aspect
def simgr_step(*args, **kwargs):
    simgr_cli, is_instance_creater = SimgrCLI.get_instance()
    simgr_info = SimgrInfo.get_instance()

    try:
        simgr_info.get_info_from_args(*args, **kwargs)

        result = yield aspectlib.Proceed # execute the original function

        simgr_info.capture_simgr_info(args[0])
        if is_instance_creater:
            simgr_cli.del_instance()
        yield aspectlib.Return(result) # return the result
    except:
        if is_instance_creater:
            simgr_cli.del_instance()
        raise





@aspectlib.Aspect
def simgr_run(*args, **kwargs):
    simgr_cli, is_instance_creater = SimgrCLI.get_instance()
    simgr_info = SimgrInfo.get_instance()

    try:
        simgr_info.get_info_from_args(*args, **kwargs)
        result = yield aspectlib.Proceed # execute the original function

        simgr_info.capture_simgr_info(args[0])
        if is_instance_creater:
            simgr_cli.del_instance()
        yield aspectlib.Return(result) # return the result
    except:
        if is_instance_creater:
            simgr_cli.del_instance()
        raise



@aspectlib.Aspect
def simgr_step_state(*args, **kwargs):
    simgr_cli, is_instance_creater = SimgrCLI.get_instance()
    simgr_info = SimgrInfo.get_instance()

    try:
        simgr_info.capture_simgr_info(args[0])

        result = yield aspectlib.Proceed # execute the original function
        simgr_info.capture_successor_info(result)
        if is_instance_creater:
            simgr_cli.del_instance()
        yield aspectlib.Return(result) # return the result
    except:
        if is_instance_creater:
            simgr_cli.del_instance()
        raise



# weave_context_step = aspectlib.weave(angr.sim_manager.SimulationManager.step, simgr_step)
# weave_context_run = aspectlib.weave(angr.sim_manager.SimulationManager.run, simgr_run)
# weave_context_step_state = aspectlib.weave(angr.sim_manager.SimulationManager.step_state, simgr_step_state)

class monitored_simgr():
    def __init__(self):
        pass

    def __enter__(self):
        self.weave_context_step_state = aspectlib.weave(angr.sim_manager.SimulationManager.step_state, simgr_step_state)
        self.weave_context_step = aspectlib.weave(angr.sim_manager.SimulationManager.step, simgr_step)
        self.weave_context_run = aspectlib.weave(angr.sim_manager.SimulationManager.run, simgr_run)

        self.weave_context_step_state.__enter__()
        self.weave_context_step.__enter__()
        self.weave_context_run.__enter__()
        return self

    def __exit__(self, *args):
        self.weave_context_step_state.__exit__(*args)
        self.weave_context_step.__exit__(*args)
        self.weave_context_run.__exit__(*args)
