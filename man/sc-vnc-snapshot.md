# EXIT STATUS
0 when the screenshot was written; 2 for a mistake in the arguments (also a password file that can't be read, or an
output that isn't .png); 3 when signing in failed (a wrong or missing password, or the server refused the session);
4 for anything else: no connection (refused, unreachable, timed out), a server that isn't VNC or sends what this
client can't read (an encoding it didn't ask for), or a PNG that can't be written.

# ENVIRONMENT
- `SC_VNC_PASSWORD`: the VNC password, when no `--password-file` is given.

# EXAMPLES
An iDRAC console on display 1 (port 5901), its password in a file only root can read:
```
sc-vnc-snapshot -p /root/idrac-vnc.pass idrac.example.com:5901 console.png
```
A server with no password, waiting at most 20 s for it:
```
sc-vnc-snapshot --timeout 20 vnc.example.com:5900 screen.png
```

# NOTES
Only VNC authentication's first 8 password characters count, as with every VNC server. The client asks for the Raw
encoding only, so a screenshot of a 1024x768 screen is about 3 MB over the network. It joins as a shared viewer,
so other viewers (an iDRAC allows one VNC session) aren't disconnected.
