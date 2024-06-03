# Resisting Physical Attacks

Running an application with security functions on an embedded system requires facing a new threat: physical attacks. The attacker has physical access to the system running your application, which offers many possibilities: measuring execution times, listening to the electromagnetic environment, or directly interacting with the circuit...

## Your Mission

You have been tasked with developing a PIN verification code on a microcontroller. The system receives 4 digits from 0 to 9 and must compare them to those, secret, stored on the chip.

You have been foresighted, and the memory of your chip is TIP TOP SECURE: the attacker cannot read it once the secret code is present. However, they have a copy of your application without the secret code, allowing them to prepare their attacks.

Your adversary will do everything to retrieve this secret; can you counter them?

## Setting Up the Work Environment

Before coding, you will need to set up the work environment:

- A cross-compilation chain allowing you to compile the code for the microcontroller from your PC.
- *Python* and some libraries that will be used to emulate the chip and simulate attacks.
- Use your favorite code editor. Start with [VS Code](https://code.visualstudio.com/) if you don't have any.

### Windows (Windows 10 or 11 required)

*If you don't have Windows 10 or 11, we recommend using a Linux/Ubuntu virtual machine (with VirtualBox, for example), it's free!*
We use WSL (Windows Subsystem for Linux) with the Ubuntu distribution.

To install WSL/Ubuntu support, launch a command prompt (type "cmd" in the application search, for example).

```sh
wsl --install -d Ubuntu-22.04
```

Specify a username and a password that you will remember.

Now, to launch the WSL terminal where the following commands will be entered, run the `wsl.bat` script which opens the terminal.
In this terminal, execute the Linux installation commands below.


### Linux

#### Automatic Installation (Recommended)

Install the Nix package manager (requires sudo permissions and *curl*).

```sh
curl -L https://nixos.org/nix/install | sh
```

Follow the on-screen instructions to complete the installation.

Use the *exercices/default.nix* file as the Nix configuration, for example:

```sh
cd exercices
nix-shell
```
This gives you a bash shell with everything needed to complete the exercises without modifying your system (in particular, no need for virtualenv for Python).

(default.nix is the default file searched for by nix-shell)

#### Manual Installation (because you really, really don't want to use Nix)

Let's start by installing the cross-compilation chain (commands given with apt for Debian-like systems).

```sh
sudo apt install gcc-arm-none-eabi
```

Then Python, its package manager (pip), and virtualenv.

```sh
sudo apt install python3
sudo apt install python3-pip
pip3 install virtualenv
```

We will now set up a virtualenv environment (the executable must be in PATH).

```sh
virtualenv exosenv
```

Finally, before each work session, the environment must be activated:

```sh
source exosenv/bin/activate
```

**At the end of the session**, the environment is deactivated with

```sh
deactivate
```

Within a session (after the source, before the deactivate), install the Python libraries.

```sh
pip3 install unicorn
pip3 install numpy
pip3 install pyelftools
pip3 install termcolor
```

For lesson 4, you will also need to install the deep learning libraries. Note, they are large.

```sh
pip3 install tensorflow
pip3 install keras
```

## Training Progression

The skeleton of your PIN verification application is in the **pin_verif** folder; this is what you will modify to get the final application.

There are 4 lessons, from L1 to L4, addressing different issues, to be completed in order:
- L1: First implementation of a naive PIN code.
- L2: Tearing and temporal dependence (or when time is your concern).
- L3: Defending against fault injection attacks
- L4: Defending against observation attacks

For each lesson, follow the instructions in the **Readme.en.md** of the lesson folder.