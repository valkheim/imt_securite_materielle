# Résister aux attaques physiques

Exécuter une application avec des fonctions de sécurité sur un système embarqué demande de faire face à une nouvelle menace: les attaques physiques.
L'attaquant a un accès physique au système faisant tourner votre application, ce qui lui offre de nombreuses possibilités: mesurer des temps d'exécution, écouter l'environnement électromagnétique, ou interagir directement avec le circuit ...


## Votre mission

Vous avez été chargé de développer un code de vérification de code PIN sur un microcontrôleur. Le système reçoit 4 chiffres de 0 à 9 et doit les comparer à ceux, secrets, mémorisés sur la puce.

Vous avez été prévoyant et la mémoire de votre puce est TIP TOP SECURE: l'attaquant ne peut pas la lire une fois que le code secret y est présent. Il possède toutefois une copie de votre application, sans le code secret, ce qui lui permet de préparer ses attaques.

Votre adversaire fera tout pour récupérer ce secret, saurez-vous le contrer ?

## Mise en place de l'environnement de travail

Avant de coder, il va falloir mettre en place l'environnement de travail:

- une chaine de cross-compilation permettant de compiler le code pour le microcontrôleur depuis votre pc.
- *python* et certaines bibliothèques qui seront utilisés pour émuler la puce et simuler les attaques.
- à vous d'utiliser votre éditeur de code favori. Si vous n'en avez pas, nous vous conseillons [VS Code](https://code.visualstudio.com/).

### Windows (Windows 10 ou 11 requis)

*Si pas de Windows 10 ou 11, nous vous conseillons d'utiliser une machine virtuelle Linux/Ubuntu (avec VirtualBox par exemple), c'est gratuit !*
Nous utilisons WSL (Windows Subsystem for Linux) avec la distribution Ubuntu.

Pour installer le support WSL/Ubuntu, lancez une invite de commandes (tapez "cmd" dans la recherche d'applications par exemple).
```
wsl --install -d Ubuntu-22.04
```

Spécifiez un nom d’utilisateur et un mot de passe dont vous vous souviendrez.

Maintenant pour lancer le termirnal WSL dans lequel les commandes suivantes sont entrées, exécuter le script wsl.bat qui ouvre le terminal.
Dans ce terminal, exécutez l'installation Linux ci-dessous.

### Linux

#### Installation automatique (recommandée)

Installez le gestionnaire de paquets Nix (nécessite les permissions sudo, et *curl*).

```
curl -L https://nixos.org/nix/install | sh
```

Suivre les indications à l'écran pour finaliser l'installation.

Utiliser le fichier *default.nix* comme configuration Nix, par exemple depuis le dossier *verifypin* contenant ce fichier.

```
nix-shell
```
**Attention: il ne se passe rien pendant un moment à la première exécution. C’EST NORMAL. Il faut patienter pendant que les dépendances sont téléchargées et installées.**
Vous donne un shell bash avec tout ce qu'il faut pour réaliser les exercices, et sans modifier votre système (en particulier pas besoin de virtualenv pour python).

(default.nix est le fichier par défaut recherché par nix-shell)

#### Installation manuelle (parce que vous ne voulez vraiment pas, mais vraiment pas utiliser Nix)

Commençons par installer la chaine de cross-compilation (commandes données avec apt pour Debian-like).
```
sudo apt install gcc-arm-none-eabi
```

Puis python, son gestionnaire de paquet (pip) et virtualenv.
```
sudo apt install python3
sudo apt install python3-pip
pip3 install virtualenv
```

Nous allons maintenant mettre en place un environnement virtualenv (il faut que l'exécutable soit dans PATH).
```
virtualenv exosenv
```

Enfin, avant chaque session de travail, il faut activer l'environnement:

```
source exosenv/bin/activate
```

**À la fin de la session**, l'environnement est désactivé à l'aide de

```
deactivate
```


Au sein d'une session (après le source, avant le deactivate), installer les bibliothèques python.
```
pip3 install unicorn
pip3 install numpy
pip3 install pyelftools
pip3 install termcolor
```

Pour la leçon 4, il faudra également installer les bibliothèques de deep learning. Attention, elles sont volumineuses.
```
pip3 install tensorflow
pip3 install keras
```

## Déroulé de la formation

Le squelette de votre application de vérification de code PIN se trouve dans le dossier **pin_verif**, c'est celui-ci que vous modifierez pour obtenir l'application finale.

Il y a 4 leçons, de L1 à L4 permettant d'approcher différentes problématiques, à réaliser dans l'ordre:
- L1: Première implémentation d’un code PIN naïf.
- L2: Arrachage et dépendance temporelle (ou quand le temps est votre souci).
- L3: Lutter contre les attaques par injection de faute
- L4: Lutter conte les attaques par observation

Pour chaque leçon, suivre les instructions dans le **Readme.md** du dossier de la leçon.




