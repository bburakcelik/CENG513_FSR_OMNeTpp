# Fisheye State Routing (FSR) Protocol Implementation in OMNeT++ for MANETs

This repository contains an implementation and evaluation of the Fisheye State Routing (FSR) protocol in OMNeT++ for Mobile Ad Hoc Networks (MANETs).

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Implementing the FSR Simulation](#implementing-the-fsr-simulation)
- [Running Simulations](#running-simulations)
- [Project Structure](#project-structure)
- [References](#references)
- [License](#license)

---

## Overview

FSR (Fisheye State Routing) is a proactive routing protocol designed for wireless ad hoc networks, particularly MANETs. This project provides an FSR implementation tailored for the OMNeT++ simulation environment.

## Prerequisites

- **OMNeT++** (version 5.x or 6.x recommended)
- **INET Framework** (compatible with your OMNeT++ version)
- **C++ Compiler** (e.g., GCC or Clang)
- Basic knowledge of OMNeT++, INET, and simulation configuration.

## Installation & Setup

### 1. Clone the Repository

```sh
git clone https://github.com/bburakcelik/CENG513_FSR_OMNeTpp.git
```

### 2. Prepare INET for FSR Integration

1. **Locate your INET source directory.**  
   Typically, this is `~/inet4/src/inet` or similar based on your OMNeT++ installation.

2. **Copy FSR Source Files:**

   - Copy the `src/node` folder from this repository to INET's node directory:
     ```sh
     cp -r CENG513_FSR_OMNeTpp/src/node <INET_ROOT>/src/inet/node/fsr
     ```
   - Copy the `src/routing` folder to INET's routing directory:
     ```sh
     cp -r CENG513_FSR_OMNeTpp/src/routing <INET_ROOT>/src/inet/routing/fsr
     ```

### 3. Rebuild INET

- Inside your INET root directory:
  ```sh
  make makefiles
  make
  ```

### 4. Set Up the Simulation Project

1. **Create a New OMNeT++ Project:**

   - In OMNeT++ IDE: `File` > `New` > `OMNeT++ Project`
   - Name it as you wish (e.g., `FSR_Simulation`).

2. **Copy Simulation Files:**

   - Copy the entire `src/simulations` directory from this repository into your new project's `simulations` folder:
     ```sh
     cp -r CENG513_FSR_OMNeTpp/src/simulations <YOUR_PROJECT_ROOT>/simulations
     ```
   - Ensure your project references the rebuilt INET framework.

## Implementing the FSR Simulation

1. **Follow the steps in [Installation & Setup](#installation--setup) above.**
2. **Configure simulation parameters** as required in the `.ini` files provided under the `simulations` folder.
3. **Custom experiments:** Modify or create new `.ned` and `.ini` files based on your research needs.

## Running Simulations

1. Open your OMNeT++ IDE and load your project.
2. Build the project to ensure all sources are compiled.
3. Select a simulation configuration from the `simulations` folder.
4. Run the simulation via the OMNeT++ IDE or using the command line:
   ```sh
   opp_run -u Cmdenv -f simulations/<config_file>.ini
   ```

## Project Structure

```
CENG513_FSR_OMNeTpp/
├── src/
│   ├── node/        # FSR node implementation (to copy to INET)
│   ├── routing/     # FSR routing implementation (to copy to INET)
│   └── simulations/ # Example and experiment simulation configs
└── README.md
```

## Notes & Recommendations

- **Back up your INET framework** before copying new protocol files.
- Review and update your OMNeT++ and INET paths as needed.
- Ensure simulation configuration files (`.ini`) reference the correct module paths.
- Examine the example simulations for parameter usage and network topology examples.

## References

- [OMNeT++ Documentation](https://doc.omnetpp.org/)
- [INET Framework](https://inet.omnetpp.org/)
- Fisheye State Routing Protocol: [Original Paper](https://ieeexplore.ieee.org/document/844318)

## License

This project is licensed under the GPLv3 License. See [LICENSE](LICENSE) for details.
