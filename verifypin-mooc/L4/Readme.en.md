# Attacker Model

An observational attack measures the physical environment of the circuit to try to gain information about the computation that is taking place. This often involves measuring the power consumption or electromagnetic radiation.

In this exercise, information leakage will be simulated: the attacker is able to recover the Hamming weight of the sum of all internal registers of the chip for each instruction in *verify_pin* and *compare_arrays* (the sum, not the values individually).

## Learning-based Attack

We will use a simple neural network to learn the relationship between the measured traces and the secret PIN present on the card.
Thus, the attack assumes that the attacker has a chip identical to the target on which he can measure whatever he wants.
In particular, he is capable of changing the secret PIN on his card and making as many attempts as he wants (it is enough to enter the correct PIN every two measurements).

## Work Environment

### With Nix

Use the Nix configuration from the L4 directory:

```bash
nix-shell ./L4/default.nix
```

### Installing Required Packages (Manual Mode)

The Python packages keras and tensorflow must be installed for this exercise.

```
pip3 install tensorflow
pip3 install keras
```

## Launching the Attack

This attack requires a lot of resources, a relatively powerful PC is recommended, and simulating enough PIN code verification can take a long time (between 10 minutes and several hours with a less powerful PC).

The first run will start the learning and then play the attack.
```
python3 ../L4/H-deep-learning.py .
```

To reload previous learning and only play the attack, use `--load`.

```
python3 ../L4/H-deep-learning.py . --load
```

### Attack Procedure

The attack begins by asking you for a candidate PIN code.
Since you do not know the correct one, you enter one at random.

During the verification of this candidate PIN, we measure the chip's consumption and compare it to our learned model.
This allows the program to suggest a new candidate that you can try.

It might be the right one!
If not, thanks to the measurement during this new verification, the program will suggest another possibility, and so on.

## Countermeasure

But then how can one protect against such an attack?
Hint: it is not possible to manipulate the secret directly in *VerifyPin* and *CompareArrays*!