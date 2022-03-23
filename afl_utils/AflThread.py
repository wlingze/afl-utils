"""
Copyright 2015-2021 @_rc0r <hlt99@blinkenshell.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import subprocess

import afl_utils

import threading


class crash_item:
    def __init__(self):
        self.crash_sample = ""
        self.classification = ""
        self.faulting_instruction = ""
        self.short_description = ""
        self.hash = ""
        self.stack_depth = 0
        self.stack_frame = []
    
    def set_item(self, sig, attr):
        if sig == 0:
            self.crash_sample = attr
        elif sig == 1:
            self.classification = attr
        elif sig == 2:
            self.faulting_instruction = attr
        elif sig == 3:
            self.short_description = attr
        elif sig == 4:
            self.hash += attr
        elif sig == 5:
            self.hash += attr
        elif sig == 6:
            self.stack_depth = int(attr)
        elif sig == 7:
            self.stack_frame.append(attr)
    

class VerifyThread(threading.Thread):
    def __init__(self, thread_id, timeout_secs, target_cmd, in_queue, out_queue, in_queue_lock, out_queue_lock):
        threading.Thread.__init__(self)
        self.id = thread_id
        self.timeout_secs = timeout_secs
        self.target_cmd = target_cmd
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.in_queue_lock = in_queue_lock
        self.out_queue_lock = out_queue_lock
        self.exit = False

    def run(self):
        while not self.exit:
            self.in_queue_lock.acquire()
            if not self.in_queue.empty():
                cs = self.in_queue.get()
                self.in_queue_lock.release()

                cmd = self.target_cmd.replace("@@", os.path.abspath(cs))
                cs_fd = open(os.path.abspath(cs))
                try:
                    if afl_utils.afl_collect.stdin_mode(self.target_cmd):
                        v = subprocess.call(cmd.split(), stdin=cs_fd, stderr=subprocess.DEVNULL,
                                            stdout=subprocess.DEVNULL, timeout=self.timeout_secs)
                    else:
                        v = subprocess.call(cmd.split(), stderr=subprocess.DEVNULL,
                                            stdout=subprocess.DEVNULL, timeout=self.timeout_secs)
                    # check if process was terminated/stopped by signal
                    if not os.WIFSIGNALED(v) and not os.WIFSTOPPED(v):
                        self.out_queue_lock.acquire()
                        self.out_queue.put((cs, 'invalid'))
                        self.out_queue_lock.release()
                    else:
                        # need extension (add uninteresting signals):
                        # following signals don't indicate hard crashes: 1
                        # os.WTERMSIG(v) ?= v & 0x7f ???
                        if (os.WTERMSIG(v) or os.WSTOPSIG(v)) in [1]:
                            self.out_queue_lock.acquire()
                            self.out_queue.put((cs, 'invalid'))
                            self.out_queue_lock.release()
                        # debug
                        # else:
                        #     if os.WIFSIGNALED(v):
                        #         print("%s: sig: %d (%d)" % (cs, os.WTERMSIG(v), v))
                        #     elif os.WIFSTOPPED(v):
                        #         print("%s: sig: %d (%d)" % (cs, os.WSTOPSIG(v), v))
                except subprocess.TimeoutExpired:
                    self.out_queue_lock.acquire()
                    self.out_queue.put((cs, 'timeout'))
                    self.out_queue_lock.release()
                except Exception:
                    pass
                cs_fd.close()
            else:
                self.in_queue_lock.release()
                self.exit = True


class GdbThread(threading.Thread):
    def __init__(self, thread_id, gdb_cmd, out_dir, output_file, grep_for, out_queue, out_queue_lock):
        threading.Thread.__init__(self)
        self.id = thread_id
        self.gdb_cmd = gdb_cmd
        self.out_dir = out_dir
        self.output_file = output_file
        self.out_queue = out_queue
        self.out_queue_lock = out_queue_lock
        self.grep_for = grep_for

    def run(self):
        try:
            subprocess.check_output(" ".join(self.gdb_cmd), shell=True, stderr=subprocess.DEVNULL,
                                    stdin=subprocess.DEVNULL)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            print(e.output)


        script_output = []
        with open(self.output_file) as f:
            script_output = f.readlines()
                
        crash = crash_item()
        for line in script_output:
            line = line.replace("\n", "")
            for i in range(8):
                grep = self.grep_for[i]
                if grep in line:
                    if i == 0:
                        self.out_queue_lock.acquire()
                        self.out_queue.put(crash)
                        self.out_queue_lock.release()
                        crash = crash_item()
                    crash.set_item(i, line.replace(grep, ""))



        # script_output = script_output.decode(errors='replace').splitlines()

        # for line in script_output:
        #     matching = [line.replace(g, '') for g in self.grep_for if g in line]
        #     matching = " ".join(matching).strip('\' ')
        #     matching = matching.replace(self.out_dir, '')
        #     if len(matching) > 0:
        #         self.out_queue_lock.acquire()
        #         self.out_queue.put(matching)
        #         self.out_queue_lock.release()


class AflTminThread(threading.Thread):
    def __init__(self, thread_id, tmin_cmd, target_cmd, output_dir, in_queue, out_queue, in_queue_lock, out_queue_lock):
        threading.Thread.__init__(self)
        self.id = thread_id
        self.target_cmd = target_cmd
        self.output_dir = output_dir
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.in_queue_lock = in_queue_lock
        self.out_queue_lock = out_queue_lock
        self.tmin_cmd = tmin_cmd
        self.exit = False

    def run(self):
        while not self.exit:
            self.in_queue_lock.acquire()
            if not self.in_queue.empty():
                f = self.in_queue.get()
                self.in_queue_lock.release()

                cmd = "%s-i %s -o %s -- %s" % (self.tmin_cmd, f, os.path.join(self.output_dir, os.path.basename(f)),
                                               self.target_cmd)
                try:
                    subprocess.call(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, shell=True)
                    self.out_queue_lock.acquire()
                    self.out_queue.put(os.path.join(self.output_dir, os.path.basename(f)))
                    self.out_queue_lock.release()
                # except subprocess.CalledProcessError as e:
                    # print("afl-tmin failed with exit code %d!" % e.returncode)
                except subprocess.CalledProcessError:
                    pass
                except Exception:
                    pass
            else:
                self.in_queue_lock.release()
                self.exit = True
