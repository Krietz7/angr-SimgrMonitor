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

# config
TIMER_ACCURATE_TO_MILLISECONDS = True
CONSOLE_LIVE_REFRESH_TIME_PER_SECOND = 50
BLOCK_EXECUTION_COUNTS_DISPLAY = 10



class Timer:
    def __init__(self):
        self.start_time = time.time()
        self.is_stopped = threading.Event()
        self.queue = Queue()
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
            time.sleep(0.03)  # 30ms Update interval

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
    def __init__(self):
        self.timer = Timer()
        self.simgr_info = SimgrInfo().get_instance()

        self.is_stopped = threading.Event()

        self.display_thread = threading.Thread(target=self._run_display)
        self.display_thread.start()


    def _run_display(self):
        with rich.live.Live(refresh_per_second=CONSOLE_LIVE_REFRESH_TIME_PER_SECOND) as live:
            while not self.is_stopped.is_set():
                try:
                    time_str = self.timer.queue.get(timeout=0.01)
                except Empty:
                    continue

                display_text = rich.text.Text.assemble(
                    ("[Timer] ", "bold cyan"),
                    (time_str, "bold green"),
                    (" | [Memory usage] ", "bold cyan"),
                    (self.simgr_info.memory_used, "bold red"),
                    ("\n"),
                    ("[Sim manager stash] ", "bold cyan"),
                    (self.simgr_info.simgr_text, "bold yellow"),
                    ("\n"),
                    ("\n"),
                    (str(self.simgr_info.retrieve_block_execution_counts()))
                )

                live.update(display_text)
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
        while(cls._instance.simgr_info.need_update == True):
            time.sleep(0.1)

        if hasattr(cls, "_instance"):
            cls._instance.__del__()

        cls._restore_loggers_level()


class SimgrInfo():
    def __init__(self):
        self.project = None
        self.simgr_text = ""
        self.memory_used = ""

        self.block_execult = []


        self.need_update = False

    def recode_simgr_info(self, simgr: angr.sim_manager.SimulationManager):
        self.project = simgr._project

        self.simgr_text = str(simgr)
        self.memory_used = self._get_memory_usage()

        self.need_update = True


    def recode_state_info(self, state: angr.sim_state.SimState):
        pass

    def record_successor_info(self, stashes):
        for key in stashes.keys():
            for state in stashes[key]:
                self.block_execult.append(state.history.addr)

        self.need_update = True


    def retrieve_block_execution_counts(self):
        execult_statistics = Counter(self.block_execult)
        execult_statistics_top = execult_statistics.most_common(BLOCK_EXECUTION_COUNTS_DISPLAY)

        print_str = ""
        for address, count  in execult_statistics_top:
            address_descrition = self.project.loader.describe_addr(address)
            print_str += address_descrition + " : " + str(count) + "\n"
        return print_str

    def _get_memory_usage(self):
        process = Process(getpid())
        memory_usage = process.memory_info().vms / float(2 ** 30)
        return '{:.4f}'.format(memory_usage) + " GB"


    def clear(self):
        self.project = None
        self.simgr_text = ""
        self.need_update = False

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, "_instance"):
            cls._instance = cls()
        return cls._instance








@aspectlib.Aspect
def simgr_step(*args, **kwargs):
    simgr_cli, is_instance_creater = SimgrCLI.get_instance()
    simgr_info = SimgrInfo.get_instance()

    try:
        result = yield aspectlib.Proceed # execute the original function

        simgr_info.recode_simgr_info(args[0])
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
        result = yield aspectlib.Proceed # execute the original function

        simgr_info.recode_simgr_info(args[0])
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
        simgr_info.recode_simgr_info(args[0])

        result = yield aspectlib.Proceed # execute the original function
        simgr_info.record_successor_info(result)
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

class RichCli:
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