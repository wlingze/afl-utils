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

import argparse
import os
import shutil
import subprocess
import sys
import threading
import time
import queue

import afl_utils
from afl_utils import afl_collect, afl_vcrash, AflThread
from afl_utils.AflPrettyPrint import clr, print_ok, print_warn, print_err


def show_info():
    print(clr.CYA + "afl-minimize " + clr.BRI + "%s" % afl_utils.__version__ + clr.RST + " by %s" %
          afl_utils.__author__)
    print("Corpus minimization utility for afl-fuzz corpora.")
    print("")


def convert_mem_limit(mem_limit):
    if mem_limit is not None:
        if mem_limit == "none":
            return "none"
        else:
            try:
                return int(mem_limit)
            except ValueError as verr:
                print_err("Converting mem-limit to int failed. Please use either \"none\" or a valid integer")
                raise verr


def invoke_cmin(input_dir, output_dir, target_cmd, mem_limit=None, timeout=None, qemu=False):
    success = True
    cmin_cmd = "afl-cmin "

    if mem_limit is not None:
        cmin_cmd += "-m %s " % convert_mem_limit(mem_limit)

    if timeout is not None:
        cmin_cmd += "-t %d " % int(timeout)

    if qemu:
        cmin_cmd += "-Q "

    cmd = "%s-i %s -o %s -- %s" % (cmin_cmd, input_dir, output_dir, target_cmd)
    print_ok("Executing: %s" % cmd)
    try:
        subprocess.check_call(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        print_warn("afl-cmin failed with exit code %d!" % e.returncode)
        success = False
    return success


def invoke_tmin(input_files, output_dir, target_cmd, num_threads=1, mem_limit=None, timeout=None, qemu=False):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    in_queue_lock = threading.Lock()
    out_queue_lock = threading.Lock()
    in_queue = queue.Queue(len(input_files))
    out_queue = queue.Queue(len(input_files))

    # fill input queue with input files
    in_queue_lock.acquire()
    for f in input_files:
        in_queue.put(f)
    in_queue_lock.release()

    thread_list = []

    tmin_cmd = "afl-tmin "

    if mem_limit is not None:
        tmin_cmd += "-m %s " % convert_mem_limit(mem_limit)

    if timeout is not None:
        tmin_cmd += "-t %d " % int(timeout)

    if qemu:
        tmin_cmd += "-Q "

    if len(input_files) > 0:
        print_ok("Executing: %s -i %s/* -o %s/* -- %s" % (tmin_cmd, os.path.dirname(input_files[0]),
                                                          output_dir, target_cmd))

    for i in range(0, num_threads, 1):
        t = AflThread.AflTminThread(i, tmin_cmd, target_cmd, output_dir, in_queue, out_queue, in_queue_lock,
                                    out_queue_lock)
        thread_list.append(t)
        print_ok("Starting afl-tmin worker %d." % i)
        t.daemon = True
        t.start()

    print_ok("Be patient, afl-tmin is running. This can take hours, if not days...")

    for t in thread_list:
        t.join()

    files_processed = []

    # read processed files from output queue
    out_queue_lock.acquire()
    while not out_queue.empty():
        files_processed.append(out_queue.get())
    out_queue_lock.release()

    return len(files_processed)


def invoke_dryrun(input_files, crash_dir, timeout_dir, target_cmd, timeout=60, num_threads=1):
    invalid_samples, timeout_samples = afl_vcrash.verify_samples(num_threads, input_files, target_cmd,
                                                                 timeout_secs=timeout)

    invalid_sample_set = set(invalid_samples+timeout_samples)
    input_sample_set = set(input_files)

    crashes_set = input_sample_set - invalid_sample_set
    crashes = list(crashes_set)

    if len(crashes) > 0:
        if not os.path.exists(crash_dir):
            os.makedirs(crash_dir, exist_ok=True)

        for c in crashes:
            shutil.move(c, os.path.join(crash_dir, os.path.basename(c)))

        print_warn("Moved %d crash samples from the corpus to %s." % (len(crashes), crash_dir))

        if len(timeout_samples) > 0:
            if not os.path.exists(timeout_dir):
                os.makedirs(timeout_dir, exist_ok=True)

            for t in timeout_samples:
                shutil.move(t, os.path.join(timeout_dir, os.path.basename(t)))

            print_warn("Moved %d timeouts from the corpus to %s." % (len(timeout_samples), timeout_dir))
    return


def afl_reseed(sync_dir, coll_dir):
    fuzzer_queues = afl_collect.get_fuzzer_instances(sync_dir, crash_dirs=False)

    for fuzzer in fuzzer_queues:
        # move original fuzzer queues out of the way
        date_time = time.strftime("%Y-%m-%d-%H:%M:%S")
        queue_dir = os.path.join(sync_dir, fuzzer[0], "queue")
        queue_bak = "%s.%s" % (queue_dir, date_time)
        os.makedirs(queue_bak, exist_ok=True)

        queue_ls = os.listdir(queue_dir)

        for item in queue_ls:
            abs_item = os.path.join(queue_dir, item)
            if os.path.isfile(abs_item):
                shutil.move(abs_item, queue_bak)

        # copy newly generated corpus into queues
        print_ok("Reseeding %s into queue %s" % (os.path.basename(coll_dir), queue_dir))
        coll_ls = os.listdir(coll_dir)

        for item in coll_ls:
            abs_item = os.path.join(coll_dir, item)
            if os.path.isfile(abs_item):
                shutil.copy2(abs_item, queue_dir)

    return fuzzer_queues


def main(argv):
    show_info()

    parser = argparse.ArgumentParser(description="afl-minimize performs several optimization steps to reduce the size\n\
of an afl-fuzz corpus.", usage="afl-minimize [-c COLLECTION_DIR [--cmin [opts]] [--tmin [opts]]] [--reseed]\n \
                   [-d] [-h] [-j] sync_dir -- target_cmd\n")

    parser.add_argument("-c", "--collect", dest="collection_dir",
                        help="Collect all samples from the synchronisation dir and store them in the collection dir.",
                        default=None)
    parser.add_argument("--cmin", dest="invoke_cmin", action="store_const", const=True,
                        default=False, help="Run afl-cmin on collection dir. Has no effect without '-c'.")
    parser.add_argument("--cmin-mem-limit", dest="cmin_mem_limit", default=None, help="Set memory limit for afl-cmin.")
    parser.add_argument("--cmin-timeout", dest="cmin_timeout", default=None, help="Set timeout for afl-cmin.")
    parser.add_argument("--cmin-qemu", dest="cmin_qemu", default=False, action="store_const", const=True,
                        help="Enable qemu mode afl-cmin.")
    parser.add_argument("--reseed", dest="reseed", default=False, action="store_const", const=True,
                        help="Reseed afl-fuzz with the collected (and optimized) corpus. This replaces all sync_dir "
                             "queues with the newly generated corpus.")
    parser.add_argument("--tmin", dest="invoke_tmin", action="store_const", const=True,
                        default=False, help="Run afl-tmin on minimized collection dir if used together with '--cmin'\
or on unoptimized collection dir otherwise. Has no effect without '-c'.")
    parser.add_argument("--tmin-mem-limit", dest="tmin_mem_limit", default=None, help="Set memory limit for afl-tmin.")
    parser.add_argument("--tmin-timeout", dest="tmin_timeout", default=None, help="Set timeout for afl-tmin.")
    parser.add_argument("--tmin-qemu", dest="tmin_qemu", default=False, action="store_const", const=True,
                        help="Enable qemu mode afl-tmin.")
    parser.add_argument("-d", "--dry-run", dest="dry_run", action="store_const", const=True,
                        default=False, help="Perform dry-run on collection dir, if '-c' is provided or on \
synchronisation dir otherwise. Dry-run will move intermittent crashes out of the corpus.")
    parser.add_argument("-j", "--threads", dest="num_threads", default=1,
                        help="Enable parallel dry-run and t-minimization step by specifying the number of threads \
afl-minimize will utilize.")
    parser.add_argument("sync_dir", help="afl synchronisation directory containing multiple fuzzers and their queues.")
    parser.add_argument("target_cmd", nargs="+", help="Path to the target binary and its command line arguments. \
Use '@@' to specify crash sample input file position (see afl-fuzz usage).")

    args = parser.parse_args(argv[1:])

    if not args.collection_dir and not args.dry_run:
        print_err("No operation requested. You should at least provide '-c'")
        print_err("for sample collection or '-d' for a dry-run. Use '--help' for")
        print_err("usage instructions or checkout README.md for details.")
        return

    sync_dir = os.path.abspath(os.path.expanduser(args.sync_dir))
    if not os.path.exists(sync_dir):
        print_err("No valid directory provided for <SYNC_DIR>!")
        return

    args.target_cmd = " ".join(args.target_cmd).split()
    args.target_cmd[0] = os.path.abspath(os.path.expanduser(args.target_cmd[0]))
    if not os.path.exists(args.target_cmd[0]):
        print_err("Target binary not found!")
        return
    args.target_cmd = " ".join(args.target_cmd)

    threads = int(args.num_threads)

    if args.collection_dir:
        out_dir = os.path.abspath(os.path.expanduser(args.collection_dir))
        if not os.path.exists(out_dir) or len(os.listdir(out_dir)) == 0:
            os.makedirs(out_dir, exist_ok=True)

            print_ok("Looking for fuzzing queues in '%s'." % sync_dir)
            fuzzers = afl_collect.get_fuzzer_instances(sync_dir, crash_dirs=False)

            # collect samples from fuzzer queues
            print_ok("Found %d fuzzers, collecting samples." % len(fuzzers))
            sample_index = afl_collect.build_sample_index(sync_dir, out_dir, fuzzers, omit_fuzzer_name=True)

            print_ok("Successfully indexed %d samples." % len(sample_index.index))
            print_ok("Copying %d samples into collection directory..." % len(sample_index.index))
            afl_collect.copy_samples(sample_index)
        else:
            print_warn("Collection directory exists and is not empty!")
            print_warn("Skipping collection step...")

        if args.invoke_cmin:
            # invoke cmin on collection
            invoke_cmin(out_dir, "%s.cmin" % out_dir, args.target_cmd, mem_limit=args.cmin_mem_limit,
                        timeout=args.cmin_timeout, qemu=args.cmin_qemu)
            if args.invoke_tmin:
                # invoke tmin on minimized collection
                tmin_num_samples, tmin_samples = afl_collect.get_samples_from_dir("%s.cmin" % out_dir, abs_path=True)
                invoke_tmin(tmin_samples, "%s.cmin.tmin" % out_dir, args.target_cmd, num_threads=threads,
                            mem_limit=args.tmin_mem_limit, timeout=args.tmin_timeout, qemu=args.tmin_qemu)
        elif args.invoke_tmin:
            # invoke tmin on collection
            tmin_num_samples, tmin_samples = afl_collect.get_samples_from_dir(out_dir, abs_path=True)
            invoke_tmin(tmin_samples, "%s.tmin" % out_dir, args.target_cmd, num_threads=threads,
                        mem_limit=args.tmin_mem_limit, timeout=args.tmin_timeout, qemu=args.tmin_qemu)
        if args.dry_run:
            # invoke dry-run on collected/minimized corpus
            if args.invoke_cmin and args.invoke_tmin:
                print_ok("Performing dry-run in %s.cmin.tmin..." % out_dir)
                print_warn("Be patient! Depending on the corpus size this step can take hours...")
                dryrun_num_samples, dryrun_samples = afl_collect.get_samples_from_dir("%s.cmin.tmin" % out_dir,
                                                                                      abs_path=True)
                invoke_dryrun(dryrun_samples, "%s.cmin.tmin.crashes" % out_dir, "%s.cmin.tmin.hangs" % out_dir,
                              args.target_cmd, num_threads=threads)
            elif args.invoke_cmin:
                print_ok("Performing dry-run in %s.cmin..." % out_dir)
                print_warn("Be patient! Depending on the corpus size this step can take hours...")
                dryrun_num_samples, dryrun_samples = afl_collect.get_samples_from_dir("%s.cmin" % out_dir,
                                                                                      abs_path=True)
                invoke_dryrun(dryrun_samples, "%s.cmin.crashes" % out_dir, "%s.cmin.hangs" % out_dir, args.target_cmd,
                              num_threads=threads)
            elif args.invoke_tmin:
                print_ok("Performing dry-run in %s.tmin..." % out_dir)
                print_warn("Be patient! Depending on the corpus size this step can take hours...")
                dryrun_num_samples, dryrun_samples = afl_collect.get_samples_from_dir("%s.tmin" % out_dir,
                                                                                      abs_path=True)
                invoke_dryrun(dryrun_samples, "%s.tmin.crashes" % out_dir, "%s.tmin.hangs" % out_dir, args.target_cmd,
                              num_threads=threads)
            else:
                print_ok("Performing dry-run in %s..." % out_dir)
                print_warn("Be patient! Depending on the corpus size this step can take hours...")
                dryrun_num_samples, dryrun_samples = afl_collect.get_samples_from_dir(out_dir, abs_path=True)
                invoke_dryrun(dryrun_samples, "%s.crashes" % out_dir, "%s.hangs" % out_dir, args.target_cmd,
                              num_threads=threads)
        elif args.reseed:
            optimized_corpus = out_dir

            if args.invoke_cmin:
                optimized_corpus = optimized_corpus + ".cmin"

            if args.invoke_tmin:
                optimized_corpus = optimized_corpus + ".tmin"

            afl_reseed(sync_dir, optimized_corpus)
    else:
        if args.dry_run:
            print_ok("Looking for fuzzing queues in '%s'." % sync_dir)
            fuzzers = afl_collect.get_fuzzer_instances(sync_dir, crash_dirs=False)
            print_ok("Found %d fuzzers, performing dry run." % len(fuzzers))
            print_warn("Be patient! Depending on the corpus size this step can take hours...")
            # invoke dry-run on original corpus
            for f in fuzzers:
                for q_dir in f[1]:
                    q_dir_complete = os.path.join(sync_dir, f[0], q_dir)
                    print_ok("Processing %s..." % q_dir_complete)

                    dryrun_num_samples, dryrun_samples = afl_collect.get_samples_from_dir(q_dir_complete, abs_path=True)
                    invoke_dryrun(dryrun_samples, os.path.join(sync_dir, f[0], "crashes"),
                                  os.path.join(sync_dir, f[0], "hangs"), args.target_cmd, num_threads=threads)


if __name__ == "__main__":
    main(sys.argv)
