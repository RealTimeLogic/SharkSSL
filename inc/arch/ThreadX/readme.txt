SharkSSL(TM) ThreadX port notes
-------------------------------

- The sharkAssert function must be routed to a console/terminal if the
  code is not compiled with the macro NDEBUG.
  
- baMalloc (allocation function) and baFree (deallocation function)
  are mapped to a ThreadX byte pool that must be initialized by
  calling baSetTxBytePool prior to using SharkSSL.
  
- A one-second timer is implemented in the porting code and must be
  initialized with a call to baInitTxUnixTime, specifying current time
  as first parameter (Unix format) and number of system ticks per
  second as second parameter Users can implement baGetUnixTime() in
  any other convenient way provided that the function returns the
  32-bit time in Unix format (necessary to comply with the SSL/TLS
  standards)
