# Automotive ECU Secure Boot and Hardware Access Protection System

## Overview

This project demonstrates fundamental automotive cybersecurity concepts through a simulated ECU secure boot system and a hardware access-control module.

The software component is implemented in C using OpenSSL, while the hardware security component is designed using Verilog and verified using SystemVerilog.

## Objectives

- Verify firmware authenticity and integrity before authorizing boot.
- Prevent firmware rollback to outdated versions.
- Implement hardware-based access-control policies.
- Detect unauthorized hardware access attempts.
- Validate security mechanisms through simulation.

## Technologies Used

**Programming:** C, Verilog, SystemVerilog

**Cryptography:** RSA-PSS, SHA-256, OpenSSL

**Development Tools:** GCC, VS Code, WSL Ubuntu, Icarus Verilog

## Project Components

### 1. ECU Secure Boot Simulation

The C application performs firmware verification using RSA-PSS digital signatures and SHA-256 hashing.

Firmware is accepted only when cryptographic verification succeeds and the firmware version meets the minimum permitted version.

### 2. Anti-Rollback Protection

The system maintains a minimum permitted firmware version and rejects older signed firmware packages.

### 3. Hardware Access Control

A Verilog module implements access restrictions for protected address regions.

Unauthorized requests generate security alerts and increment a violation counter.

### 4. Functional Verification

A SystemVerilog testbench validates authorized and unauthorized hardware-access scenarios.

## Project Structure

```text
Automotive_ECU_Security/
├── main.c
├── rtl/
│   └── access_control.v
├── tb/
│   └── access_control_tb.sv
├── README.md
└── .gitignore
```

## Compilation and Execution

Install the required development tools on Ubuntu:

```bash
sudo apt update
sudo apt install build-essential libssl-dev iverilog
```

Compile the C application:

```bash
gcc -std=c11 main.c -o ecu_security -lcrypto
```

Create the local runtime directories:

```bash
mkdir -p keys firmware state
```

Initialize the ECU simulation:

```bash
./ecu_security init
```

Create a sample firmware file:

```bash
echo "AUTOMOTIVE_ECU_FIRMWARE_V1" > firmware/firmware.bin
```

Sign the firmware:

```bash
./ecu_security sign firmware/firmware.bin 1 firmware/signed.pkg
```

Verify the signed firmware:

```bash
./ecu_security verify firmware/signed.pkg
```

Run the secure boot simulation:

```bash
./ecu_security boot firmware/signed.pkg
```

## Hardware Verification

Compile the Verilog module and SystemVerilog testbench:

```bash
iverilog -g2012 -o access_test rtl/access_control.v tb/access_control_tb.sv
```

Run the simulation:

```bash
vvp access_test
```

## Security Testing

The project supports testing of:

- Genuine firmware authentication.
- Modified firmware rejection.
- Firmware rollback detection.
- Authorized hardware access.
- Unauthorized hardware access detection.

## Limitations

This project is an educational automotive cybersecurity prototype.

The C-based secure boot simulator and Verilog access-control module are independently tested components.

The project does not implement a production ECU bootloader, protected key storage, or direct hardware–software integration.

## Future Improvements

- Secure firmware-update management.
- Hardware-assisted cryptographic acceleration.
- Protected anti-rollback storage.
- Automotive ECU hardware integration.

## Security Notice

Development signing keys are generated locally and excluded from version control. They are not intended for production use.
