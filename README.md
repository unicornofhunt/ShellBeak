## Stats

### Trace execution attempts and process creation:

```
strace -f -tt -T \
  -e trace=execve,execveat,fork,vfork,clone,clone3 \
  -o exec-syscalls.log \
  /bin/bash --noprofile --norc ./shellbeak.sh > /dev/null
```

### Trace all syscalls:
```
strace -f -tt -T -yy -s 256 \
  -o all-syscalls.log \
  /bin/bash --noprofile --norc ./shellbeak.sh > /dev/null
```
### Expected output
```
cat exec-syscalls.log 
7583  20:59:39.840983 execve("/bin/bash", ["/bin/bash", "--noprofile", "--norc", "./shellbeak.sh"], 0x7ffea88b9a90 /* 46 vars */) = 0 <0.000177>
7583  21:01:35.371581 +++ exited with 0 +++
```
Only initial bash execve call.
