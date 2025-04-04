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
REFRESH_TIME_PER_SECOND = 50
BLOCK_EXECUTION_COUNTS_DISPLAY = 10
CALLSTACK_COUNTS_DISPLAY = 10
CALL_STACK_DEPETH = 3


class SimgrTimer:
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
            time.sleep(1 / REFRESH_TIME_PER_SECOND)

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
        self.timer = SimgrTimer()
        self.simgr_info = SimgrInfo().get_instance()

        self.is_stopped = threading.Event()

        self.display_thread = threading.Thread(target=self._run_display)
        self.display_thread.start()


    def _run_display(self):
        with rich.live.Live(refresh_per_second=REFRESH_TIME_PER_SECOND) as live:
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
                    (self.simgr_info.retrieve_block_execution_counts()),
                    ("\n"),
                    (self.simgr_info.retrieve_target_stash_stack_count()),
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
        if hasattr(cls, "_instance"):
            while(cls._instance.simgr_info.need_update == True):
                time.sleep(0.1)

            cls._instance.__del__()
            del cls._instance

        cls._restore_loggers_level()


class SimgrInfo():
    def __init__(self):
        self.simgr_text = ""
        self.memory_used = ""
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
        self.memory_used = self._get_memory_usage()

        self.capture_target_stash_info(simgr)

        self.need_update = True




    def capture_target_stash_info(self, simgr: angr.sim_manager.SimulationManager):
        if self._target_stash_name == None:
            return
        def get_state_callstack(state):
            stack_suffix = state.callstack.stack_suffix(CALL_STACK_DEPETH)
            callstack_description = ""

            for address in stack_suffix:
                if address == 0 or address == None:
                    break
                if callstack_description != "":
                    callstack_description += " -> "

                callstack_description += f"{self._project.loader.describe_addr(address).split(' in ')[0]}"
            return callstack_description

        stashes = simgr.stashes[self._target_stash_name]
        self._stash_callstack.clear()
        for state in stashes:
            self._stash_callstack.append(get_state_callstack(state))

        self.need_update = True

    def record_successor_info(self, stashes):
        for key in stashes.keys():
            for state in stashes[key]:
                self._block_execult.append(state.history.addr)

        self.need_update = True


    def retrieve_target_stash_stack_count(self):
        stash_stack_statistics = Counter(self._stash_callstack)
        stash_stack_statistics_top = stash_stack_statistics.most_common(BLOCK_EXECUTION_COUNTS_DISPLAY)

        print_str = ""
        for address_descrition, count in stash_stack_statistics_top:
            print_str += address_descrition + " : " + str(count) + "\n"

        for _ in range(CALLSTACK_COUNTS_DISPLAY - len(stash_stack_statistics_top)):
            print_str += "\n"


        return print_str

    def retrieve_block_execution_counts(self):
        execult_statistics = Counter(self._block_execult)
        execult_statistics_top = execult_statistics.most_common(BLOCK_EXECUTION_COUNTS_DISPLAY)

        print_str = ""
        for address, count  in execult_statistics_top:
            address_descrition = self._project.loader.describe_addr(address)
            print_str += address_descrition + " : " + str(count) + "\n"

        for _ in range(CALLSTACK_COUNTS_DISPLAY - len(execult_statistics_top)):
            print_str += "\n"

        return print_str

    def _get_memory_usage(self):
        process = Process(getpid())
        memory_usage = process.memory_info().vms / float(2 ** 30)
        return '{:.4f}'.format(memory_usage) + " GB"


    def clear(self):
        self.__init__()

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
