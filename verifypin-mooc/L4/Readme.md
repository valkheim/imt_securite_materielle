# Modèle de l'attaquant

Une attaque par observation mesure l'environnent physique du circuit pour essayer de gagner de l'information sur le calcul qui s'y déroule. Il s'agit souvent de mesurer la consommation de courant ou le rayonnement électromagnétique.

Dans cet exercice, la fuite d'information sera simulée : l'attaquant est capable de récupérer le poids de Hamming de la somme de tous les registres internes de la puce pour chaque instruction de *verify_pin* et *compare_arrays* (la somme, pas les valeurs individuellement).

## Attaque par apprentissage

Nous allons utiliser un réseau de neurones simples pour apprendre le lien entre les traces mesurées et le PIN secret présent dans la carte.
Ainsi l'attaque présuppose que l'attaquant dispose d'une puce identique à la cible sur laquelle il peut mesurer ce qu'il veut.
En particulier, il est capable de changer le PIN secret sur sa carte et de faire autant d'essais qu'il le veut (il suffit de rentrer le bon PIN toutes les 2 mesures).

## Environnement de travail

### Avec Nix

Utilisez la configuration Nix du répertoire L4 :

```bash
nix-shell ./L4/default.nix
```

### Installation des paquets nécessaires (mode manuel)

Les paquets python keras et tensorflow doivent être installés pour cet exercice.

```
pip3 install tensorflow
pip3 install keras
```

## Lancer l'attaque

Cette attaque nécessite beaucoup de ressources, un PC relativement puissant est recommandé, la simulation de suffisamment de vérification de code PIN peut être longue (entre 10min et plusieurs heures avec un PC peu puissant).

La première exécution lancera l'apprentissage puis jouera l'attaque.
```
python3 ../L4/H-deep-learning.py .
```

Pour recharger l'apprentissage précédent et seulement jouer l'attaque, utiliser `--load`.

```
python3 ../L4/H-deep-learning.py . --load
```

### Déroulé de l'attaque

L'attaque commence par vous demander un code PIN candidat.
Puisque vous ne connaissez pas le bon, vous en entrez un au hasard.

Pendant la vérification de ce PIN candidate, nous mesurons la consommation de la puce et la comparons à notre modèle appris.
Ceci permet au programme de suggérer un nouveau candidat que vous pouvez essayer.

C'est peu être le bon !
Sinon, grâce à la mesure lors de cette nouvelle vérification, le programme vous suggèrera une nouvelle possibilité, etc, etc.

## Contremesure

Mais alors comment se protéger d'une telle attaque ? 
Indice: il n'est pas possible de manipuler le secret directement dans *VerifyPin* et *CompareArrays* !
