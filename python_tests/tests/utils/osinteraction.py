import errno
import os
import platform
import sys
from threading import Thread
from time import sleep
import signal

try:
    import psutil
except ImportError:
    psutil = False

try:
    from Queue import Queue, Empty
except ImportError:
    from queue import Queue, Empty  # python 3.x

ON_POSIX = "posix" in sys.builtin_module_names


class OsInteraction(object):
    def __init__(self, use_logger=True):
        if use_logger:
            from tests.utils.logger_service import get_logger

            self.logger = get_logger("OsInteraction")
        self.output_queues = {}
        self.all_output = {}

    @staticmethod
    def unset_variable(args, variable):
        result = []
        result.extend(args)
        if variable not in args:
            return result
        location = result.index(variable)
        result.pop(location)
        if (
            len(result) > location
            and len(result[location]) > 0
            and result[location][0] != "-"
        ):
            result.pop(location)
        return result

    @staticmethod
    def set_variable(args, variable, value=None):
        result = OsInteraction.unset_variable(args, variable)
        result.append(variable)
        if value is not None:
            result.append(str(value))
        return result

    @staticmethod
    def get_variable(command, variable):
        try:
            location = command.index(variable)
        except ValueError:
            return None
        if location < len(command) - 1:
            return command[location + 1]
        else:
            return None

    def get_app_data_path(self, filename=""):
        # Do not use the logger!
        try:
            os.makedirs(self.APP_DATA_PATH)
        except Exception:
            pass
        return os.path.join(self.APP_DATA_PATH, filename)

    def print_output_continuously(self, s, prefix=""):
        def append_output(initial, extra):
            if not initial:
                return extra if extra and len(extra) > 0 else False
            elif not extra or len(extra) == 0:
                return initial
            else:
                newline = "" if initial.endswith(os.linesep) else os.linesep
                return f"{initial}{newline}{extra}"

        all_output = [False, False]
        while True:
            output = self.get_output(s)
            if output[0]:
                self.logger.debug(
                    "silent command stdout: %s<<<<%s>>>>" % (prefix, output[0])
                )
            if output[1]:
                self.logger.debug(
                    "silent command stderr: %s<<<<%s>>>>" % (prefix, output[1])
                )

            all_output[0] = append_output(all_output[0], output[0])
            all_output[1] = append_output(all_output[1], output[1])
            if s.poll() is not None:
                break
            sleep(1)
        output = s.communicate()
        if output[0]:
            self.logger.debug("silent command stdout: %s<<<%s>>>" % (prefix, output[0]))
        if output[1]:
            self.logger.debug("silent command stderr: %s<<<%s>>>" % (prefix, output[1]))
        all_output[0] = append_output(all_output[0], output[0])
        all_output[1] = append_output(all_output[1], output[1])
        self.logger.debug(
            "application stopped: stdout %s<<%s>>" % (prefix, all_output[0])
        )
        self.logger.debug(
            "application stopped: stderr %s<<%s>>" % (prefix, all_output[1])
        )
        return all_output

    def print_output_continuously_threaded(self, s, prefix=""):
        t_stdout = Thread(target=self.print_output_continuously, args=(s, prefix))
        t_stdout.daemon = True
        t_stdout.start()

    def get_output(self, p):
        return self.non_block_read(p)

    def get_all_output(self, p):
        self.get_output(p)

        if p.pid not in self.all_output:
            return None

        output = [out.strip() for out in self.all_output.get(p.pid)]
        return tuple([out if out else False for out in output])

    def non_block_read(self, process):
        if process.pid in self.output_queues:
            q_stdout = self.output_queues[process.pid][0]
            q_stderr = self.output_queues[process.pid][1]
        else:

            def enqueue_output(out, queue):
                if out:
                    for line in iter(out.readline, b""):
                        try:
                            queue.put(line.decode("utf-8"))
                        except Exception as e:
                            self.logger.exception(e)

            #                out.close()

            q_stdout = Queue()
            t_stdout = Thread(target=enqueue_output, args=(process.stdout, q_stdout))
            t_stdout.daemon = True  # thread dies with the program
            t_stdout.start()

            q_stderr = Queue()
            t_stderr = Thread(target=enqueue_output, args=(process.stderr, q_stderr))
            t_stderr.daemon = True  # thread dies with the program
            t_stderr.start()
            sleep(0.1)
            self.output_queues[process.pid] = (q_stdout, q_stderr)

        def read_queue(q):
            # read line without blocking
            empty = True
            output = ""
            try:
                while True:
                    output += "%s" % q.get_nowait()
                    if not output.endswith(os.linesep):
                        output += os.linesep
                    empty = False
            except Empty:
                if empty:
                    return False
                else:
                    return output.rstrip("\n\r")
                # return False if empty else output

        new_output = (read_queue(q_stdout), read_queue(q_stderr))

        if process.pid not in self.all_output:
            self.all_output[process.pid] = ["", ""]
        for i, new_out in enumerate(new_output):
            if not new_out:
                new_out = ""
            self.all_output[process.pid][i] = os.linesep.join(
                [self.all_output[process.pid][i], new_out]
            )

        return new_output

    def get_open_port(self):
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", 0))
        s.listen(1)
        port = s.getsockname()[1]
        s.close()
        self.logger.debug("returning port {}".format(port))
        return port

    def get_base_path(self):
        if self.is_compiled():
            return os.path.dirname(sys.argv[0])
        else:
            self.logger.debug("sys.argv %s" % sys.argv[0])
            #           base_path = os.path.dirname(os.path.dirname(sys.argv[0]))
            base_path = os.path.dirname(os.path.dirname(__file__))
            if base_path == "":
                base_path = "../../openport/services"
            return base_path


class LinuxOsInteraction(OsInteraction):
    def __init__(self, use_logger=True):
        super(LinuxOsInteraction, self).__init__(use_logger)
        home_dir = os.path.expanduser("~/")
        if len(home_dir) < 3:
            home_dir = "./"
        self.APP_DATA_PATH = os.path.join(home_dir, ".openport")

    def get_detached_process_creation_flag(self):
        return 0

    def pid_is_running(self, pid):
        """Check whether pid exists in the current process table."""
        if pid < 0:
            return False

        try:
            os.kill(pid, 0)
        except OSError as e:
            return e.errno != errno.ESRCH
        else:
            return True

    def kill_pid(self, pid, kill_signal=None):
        if kill_signal is None:
            kill_signal = signal.SIGKILL
        os.kill(pid, kill_signal)
        return True

    def get_python_exec(self):
        virtual_env_python = os.path.join(self.get_base_path(), "env/bin/python")
        if os.path.exists(virtual_env_python):
            return ["env/bin/python"]
        else:
            return ["python"]


class WindowsOsInteraction(OsInteraction):
    def __init__(self, use_logger=True):
        super(WindowsOsInteraction, self).__init__(use_logger)
        self.APP_DATA_PATH = os.path.join(os.environ["APPDATA"], "Openport")

    def pid_is_running(self, pid):
        """Check whether pid exists in the current process table."""
        return psutil.pid_exists(pid)

    def kill_pid(self, pid, signal=-1):
        # First try killing it nicely, sending Ctrl-Break. This only works if both processes are part of the same console.
        # http://msdn.microsoft.com/en-us/library/windows/desktop/ms682541(v=vs.85).aspx
        import ctypes

        if ctypes.windll.kernel32.GenerateConsoleCtrlEvent(
            1, pid
        ):  # 0 => Ctrl-C, 1 -> Ctrl-Break
            # return True
            pass

        # If that didn't work, kill it with fire.
        sleep(1)
        return os.kill(pid, 9)
        #
        # a = self.run_shell_command(['taskkill', '/pid', '%s' % pid, '/f', '/t'])
        # self.logger.debug('kill command output: %s %s' % a)
        # return a[0].startswith('SUCCESS')

    def get_python_exec(self):
        # self.logger.debug('getting python exec. Cwd: %s' % os.getcwd())
        base_dir = self.get_base_path()
        if os.path.exists(os.path.join(base_dir, "env/Scripts/python.exe")):
            return [os.path.join(base_dir, "env\\Scripts\\python.exe")]
        else:
            return ["python.exe"]


class MacOsInteraction(LinuxOsInteraction):
    pass


def is_windows():
    return platform.system() == "Windows"


def is_mac():
    return sys.platform == "darwin"


def getInstance(use_logger=True):
    if is_mac():
        return MacOsInteraction(use_logger)
    if is_windows():
        return WindowsOsInteraction(use_logger)
    else:
        return LinuxOsInteraction(use_logger)
