# Introduction aux attaques physiques

Dans cette leçon, vous allez jouer vos premières attaques contre votre implémentation.
Le but sera donc de modifier votre programme pour y résister.

Trois types d'attaques sont présentées :
- l'attaque par force brute
- l'attaque par arrachage
- l'attaque par dépendance temporelle

Deux types de contremesures sont explorées : comment implémenter un compteur d'essai et la problématique de la comparaison de tableau en temps constant.

## Implémenter un compteur d'essai

### L'attaque par force brute

Dans votre implémentation, 10000 valeurs de code PIN différentes sont possibles. Les tester toutes est en pratique très rapide.
Pour le vérifier, il suffit d'exécuter l'attaque par brute force avec
```
python3 ../L2/B-brute-force.py .
```
depuis le répertoire **pin_verif**.

Si l'attaque réussit, c'est probablement parce que vous n'avez pas implémenté de compteur d'essai.
Il s'agit de s'assurer que l'attaquant ne puisse tenter plus que quelques candidats avant que l'application ne se verrouille.

Pour cela, nous aurons besoin d'utiliser la NVM (non-volatile memory ou mémoire non volatile en français). C'est-à-dire une mémoire qui garde des données entre deux exécutions de la vérification de code PIN.
Nous avons un peu simplifié les choses en proposant deux fonctions : *load_counter* et *store_counter*, déclarées dans le fichier d'entête "nvm.h".
Leur utilisation est la suivante.

*load_counter* permet de charger la valeur du compteur sauvegardé en mémoire (la valeur initiale est choisie par le script python).
```C
uint32_t counter = load_counter();
```

*store_counter* sauvegarde le compteur en mémoire jusqu'au prochain *load_counter*.
```C
store_counter(counter);
```

Utilisez ces fonctions pour limiter à 3 essais infructueux la vérification de code PIN. Rejouer l'attaque *B-brute-force.py* pour confirmer son inefficacité.

### L'attaque par arrachage

Logiquement, cette vérification est robuste. Toutefois, l'attaquant peut décider d'interrompre le programme quand il le désire, en déconnectant l'alimentation en énergie du microcontrôleur.
Et il peut décider l'arrachage si le programme rentre dans le branchement qui traite un PIN candidat invalide. L'arrachage est un terme historique qui désigne l'arrachage d'une carte à puce de son lecteur.

Pour effectuer cette attaque, il faut que vous annotiez le moment de l'arrachage avec **ARRACHER_ICI**, à l'entrée de la branche traitant une vérification erronée.

Par exemple:

```C
if (compare_arrays(candidate_pin, secret_pin, 4) == true ) {
    //...
}
else {
    ARRACHER_ICI
    //...
}
```

Une fois l'annotation ajoutée, recompilez votre application à l'aide de *make* et jouez les deux attaques *C-attaque-arrachage-bruteforce.py* et *D-attaque-arrachage-temporelle.py*.

```
python3 ../L2/C-attaque-arrachage-bruteforce.py .
```

```
python3 ../L2/D-attaque-arrachage-temporelle.py .
```

Si une des deux attaques fonctionne, votre implémentation du compteur d'essai n'est pas robuste.
Si l'attaque D fonctionne, c'est qu'en plus d'être vulnérable à l'arrachage, vous avez une fuite d'information par dépendance temporelle.

Essayez de résister à ces attaques en durcissant votre implémentation du compteur d'essai.

## Comparaison en temps constant

### Attaques par dépendance temporelle

Si les attaques C et D ont été réalisées avec succès toutes les deux, vous avez remarqué que l'attaque D retrouve le code PIN beaucoup plus rapidement que l'attaque C.
C'est parce qu'elle utilise une fuite d'information qui vient de votre implémentation de *compare_arrays*.

L'utilisation de la dépendance temporelle comme fuite d'information ne permet pas à elle seule, en général, de retrouver le code PIN.
Toutefois, cette attaque permet de ramener le nombre maximum d'essais à 40 ce qui accélère considérablement toutes les autres attaques.

Il faut donc boucher cette fuite d'information.

Pour tester l'implémentation correcte de votre *compare_arrays*, jouez l'attaque E :

```
python3 ../L2/E-attaque-temporelle.py .
```

Cette attaque va tenter de retrouver le code PIN en moins de 40 essais. Si elle fonctionne, c'est que votre implémentation de *compare_arrays* peut être améliorée.

Essayez de la modifier, pour que cette comparaison soit faite en temps constant et résiste à l'attaque E.
