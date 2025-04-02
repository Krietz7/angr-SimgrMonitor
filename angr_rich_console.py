# angr_decorator.py
import angr
import logging

import time
import threading

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


class SimgrConsoleLive():
    def __init__(self):
        self.timer = Timer()
        
        self.simgr_text = ""


        
        self.is_stopped = threading.Event()
        
        self.display_thread = threading.Thread(target=self._run_display)
        self.display_thread.start()

    def set_simgr_text(self, text: str):
        self.simgr_text = text

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
                    (" | [sim manager] ", "bold cyan"),
                    (self.simgr_text, "bold yellow")
                )

                live.update(display_text)

    def stop(self):
        """ Stop displaying and clean up resources """
        self.is_stopped.set()
        self.timer.stop()
        self.display_thread.join()

    def __del__(self):
        self.stop()


    @classmethod
    def get_instance(cls):
        is_new_instance = False
        if not hasattr(cls, "_instance"):
            cls._instance = cls()
            is_new_instance = True
            

        # disable angr logger
        logging.getLogger("angr").propagate = False
        return cls._instance, is_new_instance

    @classmethod
    def del_instance(cls):
        if hasattr(cls, "_instance"):
            cls._instance.__del__()

        # recover angr logger
        logging.getLogger("angr").propagate = True





@aspectlib.Aspect
def simgr_step(*args, **kwargs):
    simg_logger, is_instance_creater = SimgrConsoleLive.get_instance()

    result = yield aspectlib.Proceed
    if is_instance_creater:
        simg_logger.del_instance()
    yield aspectlib.Return(result)



@aspectlib.Aspect
def simgr_run(*args, **kwargs):
    simg_logger, is_instance_creater = SimgrConsoleLive.get_instance()

    result = yield aspectlib.Proceed
    if is_instance_creater:
        simg_logger.del_instance()
    yield aspectlib.Return(result)



@aspectlib.Aspect
def simgr_step_state(*args, **kwargs):
    simg_logger, is_instance_creater = SimgrConsoleLive.get_instance()
    simg_logger.set_simgr_text(str(args[0]))

    result = yield aspectlib.Proceed
    if is_instance_creater:
        simg_logger.del_instance()
    yield aspectlib.Return(result)




weave_context_step = aspectlib.weave(angr.sim_manager.SimulationManager.step, simgr_step)
weave_context_run = aspectlib.weave(angr.sim_manager.SimulationManager.run, simgr_run)
weave_context_step_state = aspectlib.weave(angr.sim_manager.SimulationManager.step_state, simgr_step_state)
