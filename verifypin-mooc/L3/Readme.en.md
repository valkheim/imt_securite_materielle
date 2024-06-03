# Fault Injection Attacks

In this lesson, the attacker has the means to inject faults during the execution of your program. That is, they have the ability to skip an instruction (which is then not executed).

## Direct Attack

In this first attack, a fault injection is carried out for all the instructions of *verify_pin* and *compare_arrays*. That means the PIN code verification is executed with one less instruction, a different one each time. The result of the verification can be modified as a result.

To execute this attack F,

```
python3 ../L3/F-attaque-faute-directe.py .
```

You can explore the instructions of your application by opening the file */bin/pin.list*.


How can you modify your implementation to resist this attack? There is at most one faulty instruction per PIN code verification.

## Attack on the Counter

Another way for the attacker to use fault injection is to target the counter to obtain enough attempts to find the PIN code.

Attack G works as follows:
 - first, the attacker tests all the addresses (with an instruction skip) to find those that prevent decrementing.
 - then, the attacker chooses one of these addresses and performs a brute force attack with a fault injection to prevent the counter from decrementing.

Either the PIN code is found, or the next address is tested.

This attack can be executed with

```
python3 ../L3/G-attaque-faute-compteur-bruteforce.py .
```

To resist this, you will need to harden the counter.