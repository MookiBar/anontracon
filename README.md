# About

AnonTraCon (a.k.a Anonymous Traffic Control, a.k.a ATC) is a desktop frontend written in PyQt and intended to help users manage and track their network traffic over The Onion Router (TOR). A flag icon will display in the tray of your desktop session showing the current country used as an exit node. Clicking on this icon will provide further settings to adjust your TOR settings.

This program interfaces with the STEM framework for communication with the TOR stack. It will require the initiation of an agent in the background with full permissions to TOR and/or STEM (usually as root).


# Requirements

  * Python 2.7 (python3 version in progress)
  * PyQt4
  * Bash (if using the included starter scripts)
  * ZeroMQ

# Sample Execution & Output

The agent needs to run in the background as root.
The client can run in the background as the currend desktop-session user.

The easiest way to start these is to first start the agent as root using the included script...

```
sudo bash ./usr/bin/anontracon_agent
```
...and then start the client...
```
bash ./usr/bin/anontracon_client
```


