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
