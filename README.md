# simply-cpp-vnc-snapshot

A C++20 VNC (RFB 3.3, 3.7 and 3.8) client for one screenshot, and `sc-vnc-snapshot`, the program
built on it: connect to a VNC server (an iDRAC console, say), sign in, take the whole screen once,
write it as a PNG and disconnect.

- Security: none (type 1) or VNC authentication (type 2, DES of the server's challenge; DES is built
  in, as OpenSSL 3 keeps it in its legacy provider).
- A shared viewer (ClientInit shared = 1), so other viewers stay connected: an iDRAC allows one VNC
  session.
- 32-bit true colour, Raw encoding only; bell, cut text, colour map and DesktopSize messages are
  read past.
- Depends on sc-core, sc-geometry and zlib (for the PNG), nothing else.

## Program

```sh
sc-vnc-snapshot -p /root/vnc.pass vnc.example.com:5901 console.png
```

The password comes from `--password-file` (its first line) or the `SC_VNC_PASSWORD` environment
variable, never the command line, and is never printed. `--timeout` sets how long the server may
stay silent (60 s; connecting waits at most 15 s). Exit status: 0 written, 2 usage, 3 signing in
failed (wrong or missing password, session refused), 4 no connection or a protocol problem.
`man sc-vnc-snapshot` has the rest.

## Library

```cmake
find_package(sc-vnc-snapshot 1.0.0 REQUIRED CONFIG)
target_link_libraries(app PRIVATE sc::sc-vnc-snapshot-shared)
```

```cpp
#include <sc/vnc-snapshot/vnc.h>

sc::vnc::client vnc{"vnc.example.com", 5901, {.password = password}};
std::cout << vnc.desktop_name() << ' ' << vnc.screen_size() << '\n'; // [1024,768]
const sc::vnc::picture screen = vnc.snapshot();
screen.save_png("console.png");      // or screen.png() for the bytes, screen.pixel({x, y}) for a colour
```

`sc::vnc::snapshot(host, port, options)` does it in one call. Failures are exceptions:
`sc::vnc::connect_error` (refused, unreachable, timed out), `sc::vnc::auth_error` (wrong or missing
password, session refused) and `sc::vnc::protocol_error` (silence past the read timeout, an encoding
it didn't ask for, anything else it can't follow); all derive from `sc::vnc::error`.

## Build and test

`scripts/install.sh` builds, tests and installs; `scripts/deploy.sh <server>` builds the packages
on a build server. The tests run a small RFB server in the same process. Licence: Apache 2.0.
