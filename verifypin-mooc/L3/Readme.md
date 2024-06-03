# Attaques par injection de faute

Dans cette leçon, l'attaquant a les moyens d'injecter des fautes lors de l'exécution de votre programme. C'est-à-dire qu'il a la possibilité de sauter une instruction (qui n'est donc pas exécutée).

## Attaque directe

Dans cette première attaque, une injection de faute est réalisée pour toutes les instructions de *verify_pin* et de *compare_arrays*. C'est-à-dire que la vérification de code PIN est exécutée avec une seule instruction en moins, une différente à chaque fois. Le résultat de la vérification peut en être modifié.

Pour exécuter cette attaque F, 

```
python3 ../L3/F-attaque-faute-directe.py .
```

Vous pouvez aller explorer les instructions de votre application en ouvrant le fichier */bin/pin.list*.


Comment modifier votre implémentation pour résister à cette attaque ? Il y a au plus une instruction fautée par vérification de code PIN.


## Attaque sur le compteur

Une autre manière pour l'attaquant d'utiliser l'injection de faute est de cibler le compteur pour obtenir suffisamment d'essais pour trouver le code PIN.

L'attaque G fonctionne comme suit :
 - dans un premier temps, l'attaquant teste toutes les adresses (avec un saut d'instruction) pour trouver celles qui empêchent le décrément.
 - puis l'attaquant choisit une de ces adresses et réalise une attaque par brute force avec une injection de faute pour empêcher le décrément du compteur.

Soit le code PIN est retrouvé, soit on teste l'adresse suivante.

Cette attaque peut être exécutée avec

```
python3 ../L3/G-attaque-faute-compteur-bruteforce.py .
```

Pour y résister, il va falloir durcir le compteur.
