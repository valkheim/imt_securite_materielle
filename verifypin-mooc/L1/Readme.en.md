# Setting Up PIN Code Verification

This exercise aims to set up the emulation of a microcontroller for PIN code verification.
This setup is done in two parts:
1. The creation of the target PIN verification application, in C. We provide the infrastructure for compilation.
2. The execution of the machine, via an emulator driven in Python.

At the end of this exercise, you will be able to test your first PIN code verification.

## Discovering the Application Skeleton

Open the folder of your PIN verification application: **pin_verif**.
```
cd pin_verif
```

In this folder is a skeleton of our application.
In the **inc** subfolder are the header files, including *pin.h* which contains the signatures of the functions you will need to code.
In the **src** subfolder are the source files, in C or Thumb assembler (.s).
Feel free to look at them, however, for all exercises, only the **pin.c** file needs to be modified.

## Exercise 1

Open the **pin.c** file in your code editor.

Two classic functions are important for PIN code verification:
- **compare_arrays** aims to compare two arrays of bytes and return *true* or *false* if they are identical or not.
- **verify_pin** is there to check whether the candidate PIN is valid or not. (Here the function returns the constants VALID, INVALID, or LOCKED defined in **pin.h**). As we will see later, PIN code verification is much more than a simple comparison of byte arrays.

Do not change the names of these functions, as they are used to identify memory addresses during the attacks we will conduct in the exercises.

1. Fill in the **compare_arrays** function so that it returns *true* only if the two arrays have identical content.
2. Similarly, fill in **verify_pin**, using **compare_arrays** to check the validity of the PIN code.

## Compilation

Your application is executed on a microcontroller, so cross-compilation is necessary. That is, you compile your program for a different instruction set from that of the host machine that compiles the code. You want to compile for the Thumb instruction set of ARM Cortex-M microcontrollers.

For this, you need the 'arm-none-eabi' compilation chain (toolchain).
If your work environment is correct, simply execute
```
make
```
in the **pin_verif** folder.

## Testing Your Implementation

The microcontroller is emulated, meaning you use your machine to simulate its operation.
For this, the [Unicorn](https://www.unicorn-engine.org/) tool is used, via its Python wrapper.

To test your implementation, run the Python script *authentication.py* in the exercise folder.
Give it a try!

Navigate to the **pin_verif** folder of your implementation.

```
python3 ../L1/A-authentication.py .
```

The last point, standing alone, is necessary because it specifies the current directory as the implementation of the PIN verification to use (the application is the file **pin_verif/bin/pin.bin**).
This script asks for the PIN code until it is incorrect.

```
> Please enter your PIN: 1111
! Incorrect PIN! Remaining attempts: 3
> Please enter your PIN:
```

Press CTRL+C (simultaneously the Control and C keys) to exit the program if it does not terminate on its own.

You can test it with the correct PIN.

```
> Please enter your PIN: 3141
*** PIN accepted *** Remaining attempts: 3
```

**Perfect!** In the following lessons, you will see how to attack your verification and how to protect yourself.

## BONUS (optional): A First Attack

If your verification works, you can try the brute force attack.

```
python3 ../L1/B-brute-force.py bin/
```

This attack tests all possible PIN codes to find the correct one. It should take less than 2 minutes!

Your mission for the next lesson is to modify your implementation to resist this attack.

You will need to save an attempt counter in non-volatile memory (NVM = non-volatile memory).
Therefore, you will need to use the *store_counter* and *load_counter* functions (declared in the "nvm.h" header file) to save the counter between multiple verifications.
Furthermore, if an attack is detected, the verification must return the *LOCKED* return code instead of the *VALID*/*INVALID* pair.