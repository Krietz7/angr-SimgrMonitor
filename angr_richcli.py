# angr_decorator.py
import angr
import claripy
import logging

import time
import threading
from os import getpid
from psutil import Process


import rich
from queue import Queue, Empty
import aspectlib

CONSOLE_LIVE_REFRESH_TIME_PER_SECOND = 50




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

            time_str = (
                f"{int(hours):02d}:{int(minutes):02d}:"
                f"{int(seconds):02d}.{milliseconds:03d}"
            )

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
                    (" | [sim manager] ", "bold cyan"),
                    (self.simgr_info.simgr_text, "bold yellow")
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

    @staticmethod
    def _set_loggers_level():
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("claripy").setLevel(logging.ERROR)

    @staticmethod
    def _restore_loggers_level():
        logging.getLogger("angr").setLevel(logging.WARNING)
        logging.getLogger("claripy").setLevel(logging.WARNING)


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
        self.simgr_text = ""
        self.memory_used = ""





        self.need_update = False

    def get_info_from_simgr(self, simgr: angr.sim_manager.SimulationManager):
        self.simgr_text = str(simgr)

        self.memory_used = self._get_memory_usage()





        self.need_update = True

    def _get_memory_usage(self):
        process = Process(getpid())
        memory_usage = process.memory_info().vms / float(2 ** 30)
        return '{:.4f}'.format(memory_usage) + " GB"
        



    def clear(self):
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
    try:
        result = yield aspectlib.Proceed
        if is_instance_creater:
            simgr_cli.del_instance()
        yield aspectlib.Return(result)
    except:
        if is_instance_creater:
            simgr_cli.del_instance()
        raise





@aspectlib.Aspect
def simgr_run(*args, **kwargs):
    simgr_cli, is_instance_creater = SimgrCLI.get_instance()
    try:
        result = yield aspectlib.Proceed
        if is_instance_creater:
            simgr_cli.del_instance()
        yield aspectlib.Return(result)
    except:
        if is_instance_creater:
            simgr_cli.del_instance()
        raise



@aspectlib.Aspect
def simgr_step_state(*args, **kwargs):
    simgr_cli, is_instance_creater = SimgrCLI.get_instance()
    try:
        simgr_info = SimgrInfo.get_instance()
        simgr_info.get_info_from_simgr(args[0])

        result = yield aspectlib.Proceed
        if is_instance_creater:
            simgr_cli.del_instance()
        yield aspectlib.Return(result)
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