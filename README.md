# SHELLBEAK

![ShellBeak](/icon.png)

## What's the deal? Execless?

I am quite obsessed with stealthy offensive operations, especially when EDR is running on the host. Most of the time the EDR's telemetry/detection heavily rely on Process Events which are usually obtained by hooking exec* syscall family. That's cool. However, did you know that you can run a lot of stuff with bash built-ins that will result in NO such syscalls? NO? Take this for an example:

```
while IFS= read -r line || [[ -n "$line" ]]; do     printf '%s\n' "$line"; done 2>/dev/null < /etc/passwd
```
The above is the same as you would `cat /etc/passwd`, however, you will not have a new process created (no exec* syscall).

`read` and `printf` are builtins. Bash still makes syscalls to open/read the file and write the output.

This is not silver bullet tho! If someone is tracking different syscalls (as they should, but could be noisy!) this activity would be easily trackable ;)

Note: I do believe this is NOT novel technique and been used in the wild. However, I still there is a lot of room to "push it".

Thus the meaning of "execless" in our context, we could define as : "No additional execve/execveat calls during enumeration after Bash starts. Other syscalls still occur."

While being quite amazing, it is a double-edge sword. There are some inherit limitations that you cannot really do from bash:

The limits: `around effective sudo -l permissions, NSS/LDAP identity, file capabilities, ACL contents and binary package databases are legitimate constraints of this implementation.`

***NOTE: execve etc. is not necessary a Process Creation per say, execve replaces an existing process image; it does not itself create a process.***

## Usage

```
[!] Bash 4.4 or newer is required.
```

Run `gtfobinsupdate.sh` to generate `gtfobins.txt` file for GTFOBins enumeration.

```
chmod +x shellbeak.sh
```
Execute:
```
./shellbeak.sh
```
## What is enumerated

`Identity and local accounts`
Bash UID/EUID/group variables, `/etc/passwd`, `/etc/group`, and `UID_MIN` from `/etc/login.defs`; highlights selected group memberships and likely login accounts.

`Processes`
Visible `/proc/PID/status` and `cmdline` entries, including credentials, effective capability masks, seccomp and `NoNewPrivs` values.

`Networking`
Interface attributes from `/sys/class/net`, kernel route/address tables, TCP listeners with available process associations, and the IPv4 ARP cache.

`Permissions and mounts`
SUID/SGID files, selected writable paths and PATH directories, `/opt` entries, and mount information.

`Scheduled tasks and services`
Readable cron/anacron files, periodic and init scripts, and system-level systemd unit files and drop-ins.

`User configuration`
Known shell startup/history files, SSH file readability, cloud configuration, Git credentials/configuration, Docker configuration, and netrc files.

`Installed software`
Text-based dpkg, pacman, and APK databases; detects supported RPM database locations without decoding their contents.

`GTFOBins availability`
Checks names from a local `gtfobins.txt` against the current `PATH`.

`Secret candidates`
Searches readable text candidates for a small set of case-insensitive keywords and prints matching lines with context.

## Secrets Hunting
The search includes `/home`, `/opt`, `/etc`, `/var/backups`, `/var/www`, `/tmp`, `/srv`, `/root`, `$HOME`, and additional home directories recorded in `/etc/passwd`. Hidden files and directories are included when accessible.
The current patterns are case-insensitive substrings:
```
password
token
secret
api_key
-----BEGIN
```
Every matching line found within the scan limits is displayed, with two lines before and after it. Overlapping context is merged. Matching keywords are highlighted in red, and matching/context lines are shown without the generic 2,000-byte display clipping. Secret excerpts use Bash shell escaping, so special characters may appear escaped in the report.
The summary counts matching lines, not unique credentials. Multiple keywords on one line count as one matching line. These are candidates: examples, documentation and ordinary variable names can match, while credentials without these keywords can be missed. ShellBeak does not validate credentials or test them against a service.
The secret scanner:
Reads readable regular files and skips symbolic links.
Excludes names ending in `.log` or `.gz`, and entries named `node_modules` or `vendor`, case-insensitively.
Skips `/proc`, `/sys`, `/dev`, and `/run` trees.
Uses a NUL-byte check in the first 4 KiB as a heuristic for binary data.
Excludes its own source and files directly used as its stdout/stderr destinations. Files written downstream by a pipeline such as `tee` are not identified by this check.
Stops a file before processing a line exceeding 64 KiB, or when its approximately 4 MiB text-processing budget is exceeded. It reports that the remaining content was not checked.
There is no per-file limit on the number of displayed secret matches. The scan safeguards still apply. Counts cover only the content actually processed. The text budget is not an exact underlying I/O-byte limit because ordinary Bash line reads discard NUL bytes; the initial binary probe is also only a heuristic.

## Output limits and root behavior

`General file contents`
First 200 physical lines, reduced to 80 when running as root. Displayed lines are clipped to 2,000 bytes, and a line exceeding 64 KiB stops that file. Omissions are reported.

`Main account/mount inventories`
The main reads of `/etc/passwd`, `/etc/group`, and `/proc/mounts` have no line-count cap; the common long-line safeguards still apply.

`Cron and systemd configuration`
Up to 200 nonblank, noncomment lines per file, or 80 as root. Displayed lines are clipped to 2,000 bytes; the 64 KiB line and approximately 4 MiB text-processing safeguards also apply.

`Periodic/init scripts as root`
File and access information is shown; script bodies are omitted. Cron schedule and unit-file contents are still shown within their limits.

`Broad writable-path enumeration`
Skipped as root. For other users, displays up to five interesting entries per directory, with additional counts. Traversal continues beyond the display limit.

`/opt inventory`
Displays up to 20 entries per directory and reports omissions. Remaining eligible subdirectories are still traversed.

`Packages, processes and SUID/SGID`
Existing inventories remain enabled, including when running as root.

## Stats

### Trace execution attempts and process creation:

```
strace -f -tt -T \
  -e trace=execve,execveat,fork,vfork,clone,clone3 \
  -o exec-syscalls.log \
  /bin/bash --noprofile --norc ./shellbeak.sh > /dev/null
```

### Trace all syscalls (stats):
```
strace -f -c -o syscall-stats.log \
  /bin/bash --noprofile --norc ./shellbeak.sh > /dev/null
```
### Expected output
```
cat exec-syscalls.log 
7583  20:59:39.840983 execve("/bin/bash", ["/bin/bash", "--noprofile", "--norc", "./shellbeak.sh"], 0x7ffea88b9a90 /* 46 vars */) = 0 <0.000177>
7583  21:01:35.371581 +++ exited with 0 +++
```
Only initial bash execve call.

```
cat syscall-stats.log 
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 44.09    1.586430           0   1739202    190763 newfstatat
 13.65    0.491311           0   1381967       664 lseek
  9.30    0.334524           0    719806           read
  7.14    0.257097           0    698031    698030 ioctl
  6.80    0.244754           0    698032           rt_sigprocmask
  6.40    0.230252           0    239057    155261 faccessat2
  3.91    0.140792           0    177384           getdents64
  3.50    0.126042           1    110468        20 openat
  2.05    0.073590           0    134791           close
  1.38    0.049615           0     88907           fstat
  0.96    0.034708           0    116220         1 fcntl
  0.51    0.018418           0     46031           dup2
  0.20    0.007089           0     23909           write
  0.02    0.000763           2       282           brk
  0.02    0.000712           1       664           pipe2
  0.02    0.000616           0       797         3 access
  0.01    0.000396           0       797           geteuid
  0.01    0.000383           0       797           getegid
  0.01    0.000382           0       797           getgid
  0.01    0.000368           0       797           getuid
  0.00    0.000110           4        24           munmap
  0.00    0.000038           1        38           mmap
  0.00    0.000037           0       157           mremap
  0.00    0.000026           1        14           rt_sigaction
  0.00    0.000025           6         4           mprotect
  0.00    0.000009           3         3           getppid
  0.00    0.000006           2         3           getpid
  0.00    0.000005           1         3           prlimit64
  0.00    0.000003           3         1           futex
  0.00    0.000002           2         1           uname
  0.00    0.000002           2         1           getpgrp
  0.00    0.000002           2         1           arch_prctl
  0.00    0.000002           2         1           set_tid_address
  0.00    0.000002           2         1           set_robust_list
  0.00    0.000002           2         1           getrandom
  0.00    0.000002           2         1           rseq
  0.00    0.000001           1         1           getgroups
  0.00    0.000000           0         2           pread64
  0.00    0.000000           0         1           execve
------ ----------- ----------- --------- --------- ----------------
100.00    3.598516           0   6178994   1044742 total
```

### Performance

```
/usr/bin/time -v -o performance.txt \
  /bin/bash --noprofile --norc ./shellbeak.sh \
  > out.txt 2> errors.txt
```
Due to secret hunting this will take a lot of time.

My stats on super bloated Debian:
```
cat performance.txt
        Command being timed: "/bin/bash --noprofile --norc ./shellbeak_last.sh"
        User time (seconds): 1011.99
        System time (seconds): 129.39
        Percent of CPU this job got: 96%
        Elapsed (wall clock) time (h:mm:ss or m:ss): 19:46.54
        Average shared text size (kbytes): 0
        Average unshared data size (kbytes): 0
        Average stack size (kbytes): 0
        Average total size (kbytes): 0
        Maximum resident set size (kbytes): 9040
        Average resident set size (kbytes): 0
        Major (requiring I/O) page faults: 0
        Minor (reclaiming a frame) page faults: 2637
        Voluntary context switches: 194662
        Involuntary context switches: 29942
        Swaps: 0
        File system inputs: 6644200
        File system outputs: 11424
        Socket messages sent: 0
        Socket messages received: 0
        Signals delivered: 0
        Page size (bytes): 4096
        Exit status: 0
```

## FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY

I am not responsible for any misuse of this software.

If you choose to use ShellBeak for malicious purposes, that's only on you.

This tool is provided as-is for research, education, and authorized security testing only.

## EDR Context

I was only able to test this against MDE for Linux.

The results of the test were as expected: only logged activity was initial bash execution:

`/bin/bash ./shellbeak.sh`

*I am not considering File Creation events or events related to creation of gtfobins helper file. However, you get these there is up to you.

XDR's Timeline for the Device also confirms the above, the only relevant event would be: `shellbeak.sh was executed by bash`. I haven't noticed any additional telemetry.

I haven't received any alert too.

#### Picture (icon.png) was AI generated.
