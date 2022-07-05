NetX porting layer for selib (socket library).

Include this directory in the compiler's include path and add seNetX.c
to your build.

Function seNetX_init (in selibplat.h) must be called prior to using
this library.

The source code in seNetX.c provides a porting layer to the NetX
TCP/IP stack for all example programs.

Error codes from some of the native NetX calls in seNetX.c are
considered fatal (they should not occur) and the macro VRSP() calls
function time2Reboot() if an error is returned. You must modify function
time2Reboot() and/or macro VRSP() to suit your platform requirements.

The API provided by selib follows the typical BSD style API and makes
it possible for all example programs to be portable across all
supported TCP/IP stacks. This is true for all API calls, but special
care must be taken when using function se_accept().

BSD accept vs. NetX accept:

The BSD API takes a server listening socket and spawns a new socket
when a client connects:

int newSocket = accept(listenSocket, 0, 0);

NetX on the other hand converts listenSocket into newSocket; details:
https://docs.microsoft.com/en-us/azure/rtos/netx/chapter4#nx_tcp_server_socket_accept

The selib function se_accept is designed to be NetX compatible, but a
programmer using this function must take extra care when declaring the
socket variables. The following example illustrates how the variables
must be declared. The code is copied from WsLedServer.c, a Minnow
Server example program.

SOCKET listenSock;
SOCKET sock;
SOCKET* listenSockPtr = &listenSock;
SOCKET* sockPtr = &sock;
......
se_accept(&listenSockPtr, INFINITE_TMO, &sockPtr);

The variables listenSock and sock swaps identity after se_accept
returns. However, since we are using two pointers (listenSockPtr and
sockPtr) further down in the program, everything will work as it does
with a traditional BSD socket accept. This construction works as long
as you do not spawn threads as shown in the multi threaded Minnow
Server example MultiWsLedServer.c, which will not work with NetX. This
code would need some minor redesign when used with NetX. Instead of
declaring the sockets as variables, the socket pointers must be
dynamically allocated, e.g.

SOCKET* sock1Ptr = malloc(sizeof(SOCKET));
SOCKET* sock2Ptr = malloc(sizeof(SOCKET));
......
se_accept(&sock1Ptr, INFINITE_TMO, &sock2Ptr);

When using the Minnow Server library with one socket, an alternative to using
se_accept is to directly use the NetX native API as follows:

for(;;)
{
   SOCKET sock;
   NX_TCP_SOCKET* nsSock;
   SOCKET_constructor(&sock, NULL);
   se_bind(&sock, port);
   nsSock=&sock.nxSock;
   nx_tcp_server_socket_accept(nxSock, NX_WAIT_FOREVER);
   .....
   runServer(&ms, &wph);
   .....
   se_close(&sock);
}
