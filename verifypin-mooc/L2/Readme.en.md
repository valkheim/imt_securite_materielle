# Introduction to Physical Attacks

In this lesson, you will conduct your first attacks against your implementation.
The goal is to modify your program to resist them.

Three types of attacks are presented:
- brute force attack
- tearing attack
- time-dependence attack

Two types of countermeasures are explored: how to implement a trial counter and the issue of constant-time array comparison.

## Implementing a Trial Counter

### The Brute Force Attack

In your implementation, 10,000 different PIN code values are possible. Testing them all is very fast in practice.
To verify this, simply execute the brute force attack with
```
python3 ../L2/B-brute-force.py .
```
from the **pin_verif** directory.

If the attack succeeds, it's probably because you haven't implemented a trial counter.
This is to ensure that the attacker can only try a few candidates before the application locks.

For this, we will need to use NVM (non-volatile memory). That is, a memory that retains data between two executions of PIN code verification.
We've simplified things a bit by offering two functions: *load_counter* and *store_counter*, declared in the "nvm.h" header file.
Their usage is as follows.

*load_counter* loads the saved counter value from memory (the initial value is chosen by the python script).
```C
uint32_t counter = load_counter();
```

*store_counter* saves the counter in memory until the next *load_counter*.
```C
store_counter(counter);
```

Use these functions to limit unsuccessful PIN verification attempts to 3. Replay the *B-brute-force.py* attack to confirm its ineffectiveness.

### The Tearing Attack

Logically, this verification is robust. However, the attacker can decide to interrupt the program whenever they want, by disconnecting the microcontroller's power supply.
And they can decide on tearing if the program enters the branch that handles an invalid candidate PIN. Tearing is a historical term that refers to pulling a smart card out of its reader.

To perform this attack, you need to annotate the moment of tearing with **ARRACHER_ICI**, at the entry of the branch dealing with an erroneous verification.

For example:

```C
if (compare_arrays(candidate_pin, secret_pin, 4) == true ) {
    //...
}
else {
    ARRACHER_ICI
    //...
}
```

Once the annotation is added, recompile your application using *make* and play the two attacks *C-attaque-arrachage-bruteforce.py* and *D-attaque-arrachage-temporelle.py*.

```
python3 ../L2/C-attaque-arrachage-bruteforce.py .
```

```
python3 ../L2/D-attaque-arrachage-temporelle.py .
```

If either attack works, your implementation of the trial counter is not robust.
If attack D works, it's because, in addition to being vulnerable to tearing, you have an information leak due to time dependence.

Try to resist these attacks by hardening your implementation of the trial counter.

## Constant-Time Comparison

### Time-Dependence Attacks

If both attacks C and D were successfully carried out, you will have noticed that attack D finds the PIN code much more quickly than attack C.
This is because it uses an information leak that comes from your implementation of *compare_arrays*.

Using time dependence as an information leak, in general, does not allow the PIN code to be retrieved on its own.
However, this attack reduces the maximum number of attempts to 40, which significantly accelerates all other attacks.

Therefore, this information leak must be plugged.

To test the correct implementation of your *compare_arrays*, play attack E:

```
python3 ../L2/E-attaque-temporelle.py .
```

This attack will try to find the PIN code in less than 40 attempts. If it works, your implementation of *compare_arrays* can be improved.

Try modifying it so that this comparison is done in constant time and resists attack E.