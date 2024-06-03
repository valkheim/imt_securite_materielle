# Mise en place de la vérification de code PIN

Cet exercice a pour but de mettre en place l'émulation d'un microcontrôleur pour la vérification de code PIN.
Cette mise en place se fait en deux parties:
1. La création de l'application cible de vérification de code PIN, en C. Nous fournissons l'infrastructure pour la compilation.
2. L'exécution de la machine, via un émulateur piloté en Python.

À la fin de cet exercice, vous pourrez tester votre première vérification de code PIN.

## Découverte du squelette d'application


Ouvrez le dossier de votre application de vérification de code PIN: **pin_verif**.
```
cd pin_verif
```

Dans ce dossier se trouve un squelette de notre application.
Dans le sous-dossier **inc** se trouve les fichiers entêtes, dont *pin.h* qui contient la signature des fonctions que vous devrez coder.
Dans le sous-dossier **src** se trouvent les fichiers sources, en C ou en assembleur Thumb (.s).
N'hésitez pas à les regarder, toutefois, pour tous les exercices, seul le fichier **pin.c** a besoin d'être modifié.

## Exercice 1


Ouvrez le fichier **pin.c** dans votre éditeur de code.

Deux fonctions classiques sont importantes pour la vérification d'un code PIN:
- **compare_arrays** a pour but de comparer deux tableaux d'octets et de retourner *true* ou *false* s'ils sont identiques ou non.
- **verify_pin** est là pour vérifier que le PIN candidat est valide ou non. (Ici la fonction retourne les constantes VALID, INVALID ou LOCKED définies dans **pin.h**). Comme nous le verrons par la suite, la vérification de code PIN est bien plus qu'une simple comparaison de tableaux d'octets.

Ne changez pas les noms de ces fonctions, car ils sont utilisés pour identifier des adresses mémoires lors des attaques que nous mènerons dans les exercices.

1. Remplissez la fonction **compare_arrays** pour qu'elle retourne *true* uniquement si les deux tableaux ont un contenu identique.
2. De même, remplissez **verify_pin**, en utilisant **compare_arrays** pour vérifier la validité du code PIN.

## Compilation

Votre application est exécutée sur un microcontrôleur, il faut donc réaliser une compilation croisée. C'est-à-dire que l'on compile notre programme pour un jeu d'instruction différent de celui de la machine hôte, qui compile le code. Vous voulez compiler pour le jeu d'instruction Thumb des microcontrôleurs ARM Cortex-M.

Pour cela vous devez avoir la chaîne de compilation (*toolchain* en anglais) 'arm-none-eabi'.
Si votre environnement de travail est bon, il suffit d'exécuter
```
make
```
dans le dossier **pin_verif**.

## Tester votre implémentation

Le microcontrôleur est émulé, c'est-à-dire que vous utilisez votre machine pour en simuler le fonctionnement.
Pour cela, l'outil [Unicorn](https://www.unicorn-engine.org/) est utilisé, via son wrapper Python.

Pour tester votre implémentation, lancez le script Python *authentification.py* dans le dossier de l'exercice.
Essayez !

Placez-vous dans le dossier **pin_verif** de votre implémentation.

```
python3 ../L1/A-authentification.py .
```

Le dernier point, solitaire, est nécessaire, car il spécifie le répertoire courant comme étant l'implémentation de la vérification de code PIN à utiliser (l'application est le fichier **pin_verif/bin/pin.bin**).
Ce script demande le code PIN tant que celui-ci est incorrect.

```
> Veuillez entrer votre PIN: 1111
! PIN incorrect ! Essais restant: 3
> Veuillez entrer votre PIN:
```

Appuyer sur CTRL+C (simultanément les touches Contrôle et C), pour quitter le programme s'il ne se termine pas tout seul.

On peut tester avec le bon PIN.

```
> Veuillez entrer votre PIN: 3141
*** PIN accepté *** Essais restant: 3
```

**Parfait !** Vous verrez dans les leçons suivantes comment attaquer votre vérification, et comment vous protéger.


## BONUS (optionnel): une première attaque

Si votre vérification fonctionne, vous pouvez essayer l'attaque par force brute.

```
python3 ../L1/B-brute-force.py .
```

Cette attaque teste toutes les possibilités de code PIN pour trouver le bon. Cela doit prendre moins de 2 minutes !

Votre mission pour la prochaine leçon est de modifier votre implémentation pour résister à cette attaque.

Vous aurez besoin pour cela de sauvegarder un compteur d'essai en mémoire non volatile (NVM = non-volatile memory).
Il faudra donc utiliser les fonctions *store_counter* et *load_counter* (déclarées dans le fichier d'entête "nvm.h") permettant de sauvegarder le compteur entre plusieurs vérifications.
D'autre part, si une attaque est détectée, la vérification doit renvoyer le code de retour *LOCKED* au lieu du couple *VALID*/*INVALID*.
