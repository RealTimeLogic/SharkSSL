# SharkSSL
SharkSSL Amalgamated

SharkSSL Amalgamated is a compact version of [SharkSSL](https://realtimelogic.com/products/sharkssl/) extracted from the SharkSSL SDK. This amalgamated version of SharkSSL is intended for evaluation purposes. [For full license details, please see below](#license). SharkSSL Amalgamated includes all APIs found in the standard SharkSSL SDK. SharkSSL Amalgamated includes the following source code components.

* **SharkSSL.c**: Platform independent code (amalgamation of several files)
* **TargConfig.h**: SharkSSL porting layer.
* **selib.c**: Socket example library (optional). This library is used by all IoT protocols.
* **selibplat.h**: Socket example library porting layer. Some porting layers also include selibplat.c.
* **SeCtx.c**: Socket example library [bare metal management](https://realtimelogic.com/ba/doc/en/C/shark/group__BareMetal.html) (when not using an RTOS).

Only SharkSSL.c and TargConfig.h are required if you are directly using the [transport agnostic SharkSSL API](https://realtimelogic.com/ba/doc/en/C/shark/index.html#SharkTransportAgnosticIntro). A SharkSSL Library can be created as follows:

```
$ gcc -c src/SharkSSL.c -Iinc -Iinc/arch/Posix
$ ar -rc libsharkssl.a SharkSSL.o
```

Note that SharkSSL can be compiled using any C (cross) compiler. SharkSSL is C89 compatible.

## SharkSSL Amalgamated Limitations

SharkSSL Amalgamated does not include assembler optimized ciphers.

## Memory

SharkSSL is very efficient at using memory and a secure IoT client connection can use less than 10K total. SharkSSL manages memory by using a memory allocator. You can use any allocator, including the very efficient allocator found in the examples/malloc directory. Some of the porting layers are pre-set to use this allocator. You can change the allocator by modifying the macros in inc/arch/XXX/TargConfig.h

## IoT Protocols

The following IoT protocols are included with SharkSSL Amalgamated. Note that all protocols require selib.c and all protocols use TLS.

- **SharkMQ.c** - [Client SMQ IoT Stack](https://realtimelogic.com/products/simplemq/)
- **SharkMQTT.c** - [Client MQTT Stack](https://realtimelogic.com/products/sharkmqtt/)
- **WsClientLib.c** -  [Client WebSocket Stack](https://realtimelogic.com/products/sharkssl/websocket-client/)
- **SMTP/SMTP.c** - [SMTP (email) Library](https://realtimelogic.com/products/sharkssl/smtp/)
- **MinnowServer/MSLib.c** - The [Minnow Server](https://realtimelogic.com/products/sharkssl/minnow-server/) (WebSocket Server). We recommend using the Minnow Server Reference Example with the Minnow Server. The Minnow Server Reference Example provides a secure (HTTPS) connection when used together with SharkSSL, but [must be downloaded separately](https://github.com/RealTimeLogic/MinnowServer).

To compile SharkSSL and one of the IoT protocols, include SharkSSL.c, the required protocol, src/arch/XXX/*.c if included, where XXX is the required porting layer. In addition, the compiler's include path must include inc, inc/arch/XXX, and src/arch/XXX.

## Examples

The following lists the IoT examples included with SharkSSL Amalgamated. The examples directory includes additional examples. See the online [SharkSSL example documentation](https://realtimelogic.com/ba/doc/en/C/shark/group__SharkExamples.html) for additional details on the examples.

All examples below use TLS. We recommend reading the article [Certificate Management for Embedded Systems](https://realtimelogic.com/articles/Certificate-Management-for-Embedded-Systems) if you are new to PKI and X.509 certificate management.

- **LED-SMQ.c** - Shows how to use the [SMQ IoT Protocol](https://realtimelogic.com/products/simplemq/) for controlling LEDs on a device. The example is set up to connect to the online SMQ test broker, but can easily be changed to connect to your own broker. The SMQ protocol is ideal for IoT projects that can benefit from a low cost IoT solution. See the tutorials [How to Set up a Low Cost Online IoT Broker](https://makoserver.net/articles/Setting-up-a-Low-Cost-SMQ-IoT-Broker) and [Browser to Device LED Control using SMQ](https://makoserver.net/articles/Browser-to-Device-LED-Control-using-SimpleMQ) for details. The client SMQ protocol stack used is called [SharkMQ](https://realtimelogic.com/ba/doc/en/C/shark/group__SMQLib.html).
- **SharkTrust.c** - Shows how to use [SharkTrust](https://realtimelogic.com/services/SharkTrust/) with the Minnow Server. The example is setup to use the [SharkTrust test server domain equip.run](https://equip.run/) and requires no configuration.
- **SMTP-example.c** - Shows how to send secure emails. This example requires configuration and will not compile unless configured. See the source code for details.
- **WsEchoClient.c** - Shows how to use the [WebSocket Client Library](https://realtimelogic.com/ba/doc/en/C/shark/group__WsClientLib.html). The example expects inputs entered at the terminal when running.
- **Chat-MQTT.c** - Shows how to use the [SharkMQTT Client Library](https://realtimelogic.com/ba/doc/en/C/shark/group__MQTTLib.html). The example expects inputs entered at the terminal when running and works best if two or more clients run simultaneosly. See the source code for details.
- **AWS-MQTT.c** - Shows how to connect to Amazon's AWS IoT Core using the MQTT protocol. This example requires configuration. See the source code for details.

## Testing the Examples

The SharkSSL TLS stack and the included protocol stacks are mainly designed for embedded devices but can also be compiled for Windows and Linux. Below is an example demonstrating how to compile and run two examples on Linux and the Windows Subsystem for Linux (WSL).

Start by installing the required tools and cloning the repository:

``` shell
sudo apt install git gcc
git clone https://github.com/RealTimeLogic/SharkSSL
cd SharkSSL/
```

How to compile the MQTT Chat Example:

``` shell
# Compile SharkSSL, SharkMQTT, the socket lib, and the chat example
gcc -o Chat-MQTT -Iinc -Iinc/arch/Posix -Isrc/arch/Posix \
    src/SharkSSL.c src/SharkMQTT.c src/selib.c examples/Chat-MQTT.c
# Start the MQTT chat example
./Chat-MQTT
```

How to compile the [SMQ LED Example](https://makoserver.net/articles/Browser-to-Device-LED-Control-using-SimpleMQ):

``` shell
# Compile SharkSSL, SharkMQ (secure SMQ), the socket lib, and the chat example
gcc -o LED-SMQ -Iinc -Iinc/arch/Posix -Isrc/arch/Posix \
    src/SharkSSL.c src/SharkMQ.c src/selib.c examples/LED-SMQ.c
# Start the example
./LED-SMQ
```

## Makefile

A basic makefile for Linux is included. The makefile shows how to build the [SharkSSL command line tools](https://realtimelogic.com/ba/doc/en/C/shark/md_md_Certificate_Management.html#CertificateTools) and most of the examples. The command line tools can also be compiled for Windows. Note that the examples requiring configuration will not work when compiled without modifications. The SMTP-example.c produces a compile error when not configured.

## SharkSSL IDE

For FreeRTOS users: check out the super easy to use [SharkSSL IDE](https://realtimelogic.com/downloads/sharkssl/ESP32/) designed for educational purposes.

## License

SharkSSL Amalgamated is either licensed for use under the GPLv2 or a
standard commercial license. For our users who cannot use SharkSSL
Amalgamated under GPLv2, a
[commercial license is available](https://realtimelogic.com/contactus/license/). A
free commercial license for small companies is available.  See the
startup license page for details:
https://realtimelogic.com/startuplic/

## Export restrictions

This distribution includes cryptographic software.  The country in 
which you currently reside may have restrictions on the import, 
possession, use, and/or re-export to another country, of 
encryption software.  BEFORE using any encryption software, please 
check your country's laws, regulations and policies concerning the
import, possession, or use, and re-export of encryption software, to 
see if this is permitted.  See http://www.wassenaar.org/ for more
information.

The U.S. Government Department of Commerce, Bureau of Industry and
Security (BIS), has classified this software as Export Commodity
Control Number (ECCN) 5D002.C.1, which includes information security
software using or performing cryptographic functions with asymmetric
algorithms.  The form and manner of this distribution makes it
eligible for export under the License Exception ENC Technology
Software Unrestricted (TSU) exception (see the BIS Export
Administration Regulations, Section 740.13) for both object code and
source code.
