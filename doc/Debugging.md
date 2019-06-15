# Debugging

**There three channels for debugging with different intended verbosity:**
  1. system log,which also appears with logread or dmesg. This can be accessed with bmx7 -cd0. 
  2. Event logs are more verbose they are used for tracking of events and triggered with code dbgf_track(...). They can be accessed with command bmx7 -cd3.
  3. Most verbose logs coded with dbgf_all(). Can be accessed with command bmx7 -cd4. (But for embedded devices these logs are often compiled out with a NODEBUGALL Macro or so.

- All system logs also end up as track logs and all-logs.
- Track logs also end up in all logs.

**There are three different flags for logs:**
  1. DBGT_INFO, 
  2. DBGT_WARN, 
  3. DBGT_ERR. 
  
These are just used to unify the severity level with which the log appears.
