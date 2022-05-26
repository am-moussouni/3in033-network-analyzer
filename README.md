## Description du programme :

Il s'agit d'un analyseur de protocoles réseau ‘offline’. Il prend en entrée un fichier trace contenant une ou plusieurs trames constituées d'octets capturés sur un réseau Ethernet grâce à l'outil Wireshark. En sortie, on aura un fichier texte formaté qui décode chacun des protocoles des différentes trames.



Lien de la vidéo YouTube de présentation : https://www.youtube.com/watch?v=E2g_l01dzBk

## Prérequis

Ce programme utilise le langage de programmation Python. Il faut donc avoir s

* python3 (ne fonctionne pas sous python2)
* les libraries python3 : contextlib, codecs et sys

## Lancement

* Dézipper le fichier et se mettre dans le dossier dézippé
* Ouvrir un terminal
* Lancer la commande :

  ```
  python3 Analyseur.py <nom_du_fichier_trame>
  ```

Attention : Il faut que le fichier contenant la trame soit dans le même dossier que Analyseur.py.

## Résultat

Le décodage est lisible directement dans un fichier sauvegardé sous le nom de resultat.txt. Il n'est pas affiché sur le terminal.