# SharkSSL Amalgamated

[SharkSSL](https://realtimelogic.com/products/sharkssl/) is a compact embedded TLS 1.3 and TLS 1.2 client and server stack for devices where code size, memory use, and portability matter. This repository packages the SharkSSL core, porting layers, examples, command-line tools, and complementary application-protocol libraries in a source layout that is easy to add to an embedded C or C++ project.

SharkSSL Amalgamated includes the APIs provided by the standard SharkSSL SDK, except for assembler-optimized ciphers. For API details and integration guidance, use the [official SharkSSL documentation](https://realtimelogic.com/ba/doc/en/C/shark/index.html). This README focuses on what the repository contains and how to get started.

## Included protocol libraries

All five complementary protocol libraries shipped in `src` are listed below. They are included free of charge and are designed to work with SharkSSL when secure transport is required. Their use remains subject to the [SharkSSL Amalgamated license terms](#license).

| Library | Source | What it provides | Official documentation |
| --- | --- | --- | --- |
| SharkMQ | `src/SharkMQ.c` | Secure SimpleMQ publish/subscribe client | [SharkMQ API](https://realtimelogic.com/ba/doc/en/C/shark/group__SMQLib.html) |
| SharkMQTT | `src/SharkMQTT.c` | Secure, compact MQTT client for embedded systems | [SharkMQTT API](https://realtimelogic.com/ba/doc/en/C/shark/group__MQTTLib.html) |
| WebSocket Client Lib | `src/WsClientLib.c` | Compact WebSocket client with HTTP upgrade support | [WebSocket Client API](https://realtimelogic.com/ba/doc/en/C/shark/group__WsClientLib.html) |
| SMTP | `src/SMTP/SMTP.c` | Email client supporting SMTPS and STARTTLS | [SMTP API](https://realtimelogic.com/ba/doc/en/C/shark/group__SMTP.html) |
| Minnow Server | `src/MinnowServer/MSLib.c` | Compact HTTP(S) and WebSocket server | [Minnow Server API](https://realtimelogic.com/ba/doc/en/C/shark/group__MSLib.html) |

The optional `src/SMTP/BufPrint.c` and `src/MinnowServer/ZipFileSystem.c` files support the SMTP and Minnow Server libraries. The complete [Minnow Server reference example](https://github.com/RealTimeLogic/MinnowServer) is maintained in a separate repository.

## Looking for SSH?

[SharkSSH](https://github.com/RealTimeLogic/SharkSSH) is a separate embedded SSH server project for applications that need SSH or SFTP. SharkSSH is not included in this repository.

## Core source and porting layers

The main SharkSSL components are:

- `src/SharkSSL.c`: Platform-independent amalgamated TLS implementation.
- `inc/SharkSSL.h`: Public SharkSSL API.
- `inc/arch/<platform>/TargConfig.h`: Compile-time configuration and target porting layer.
- `src/selib.c`: Optional socket example library used by the included protocol examples.
- `src/arch/<platform>/`: Network-stack-specific support for `selib` where required.
- `src/SeCtx.c`: Optional socket context manager for bare metal systems.

Choose the integration approach that matches your platform:

- Use the [transport-agnostic SharkSSL API](https://realtimelogic.com/ba/doc/en/C/shark/index.html#SharkTransportAgnosticIntro) when your application manages network input and output directly.
- Use `selib` with the appropriate architecture port for blocking socket environments such as an RTOS or POSIX system.
- Use the [bare metal integration](https://realtimelogic.com/ba/doc/en/C/shark/group__BareMetal.html) with `SeCtx` when the system has no RTOS and uses an event-driven network stack.

SharkSSL is written in portable C and can be compiled with a native or cross compiler. For example, the POSIX configuration can be built as a static library on Linux:

```sh
gcc -c src/SharkSSL.c -Iinc -Iinc/arch/Posix
ar rcs libsharkssl.a SharkSSL.o
```

## Memory configuration

SharkSSL is designed for memory-constrained systems. A secure IoT client connection can use less than 10 KB of total memory, depending on the selected features, cipher suites, certificate chain, and buffer sizes.

SharkSSL uses a configurable memory allocator. You can use the allocator in `examples/malloc` or provide your own. Configure the allocator and other target-specific options in `inc/arch/<platform>/TargConfig.h`.

## Build and run examples on Linux

Clone the repository and enter its directory:

```sh
git clone https://github.com/RealTimeLogic/SharkSSL.git
cd SharkSSL
```

Build and run the MQTT chat example:

```sh
gcc -o Chat-MQTT -Iinc -Iinc/arch/Posix -Isrc/arch/Posix \
    src/SharkSSL.c src/SharkMQTT.c src/selib.c examples/Chat-MQTT.c
./Chat-MQTT
```

Build and run the SimpleMQ LED example:

```sh
gcc -o LED-SMQ -Iinc -Iinc/arch/Posix -Isrc/arch/Posix \
    src/SharkSSL.c src/SharkMQ.c src/selib.c examples/LED-SMQ.c
./LED-SMQ
```

For other protocols, compile `src/SharkSSL.c`, `src/selib.c`, the selected protocol source, and any files required by the selected architecture port. Add `inc`, `inc/arch/<platform>`, and `src/arch/<platform>` to the compiler's include path.

The `build/Makefile` builds the static library, command-line certificate tools, and most examples on Linux:

```sh
make -C build
```

Some examples require credentials, server addresses, certificates, or other configuration before they can be built or run. Read the comments at the top of the selected example first.

## Examples and tools

The `examples` directory includes, among others:

- `LED-SMQ.c`: Controls a device through SimpleMQ.
- `Chat-MQTT.c`: Sends and receives MQTT chat messages.
- `AWS-MQTT.c`: Connects to AWS IoT Core using MQTT; configuration is required.
- `WsEchoClient.c`: Connects to a WebSocket echo service.
- `SMTP-example.c`: Sends email using SMTP; configuration is required.
- `SharkTrust.c`: Demonstrates SharkTrust with the Minnow Server.

See the [official example documentation](https://realtimelogic.com/ba/doc/en/C/shark/group__SharkExamples.html) for setup and API details. The `tools` directory contains certificate and key conversion utilities documented under [SharkSSL certificate management](https://realtimelogic.com/ba/doc/en/C/shark/md_md_Certificate_Management.html#CertificateTools).

For an educational FreeRTOS setup, see the [SharkSSL IDE for ESP32](https://realtimelogic.com/downloads/sharkssl/ESP32/).

## License

SharkSSL Amalgamated is licensed under either GPLv2 or a standard commercial license. See [LICENSE](LICENSE) for the GPLv2 terms.

If GPLv2 is not suitable for your product, a [commercial license](https://realtimelogic.com/contactus/license/) is available. A free commercial license may be available to qualifying small companies; see the [startup license](https://realtimelogic.com/startuplic/) for details.

## Export restrictions

This distribution includes cryptographic software. The country in which you reside may restrict the import, possession, use, or re-export of encryption software. Before using this software, check the applicable laws, regulations, and policies. See the [Wassenaar Arrangement](https://www.wassenaar.org/) for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software under Export Commodity Control Number (ECCN) 5D002.C.1. This classification includes information-security software that uses or performs cryptographic functions with asymmetric algorithms. The form and manner of this distribution make it eligible for export under the License Exception ENC Technology Software Unrestricted (TSU) exception. See Section 740.13 of the BIS Export Administration Regulations for the applicable requirements.
