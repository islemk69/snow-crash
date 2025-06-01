# Snow Crash – Level00

## 🔍 Objectif  
Accéder au compte `flag00` en trouvant son mot de passe, puis récupérer le token avec `getflag`.

---

## 🧾 Étapes réalisées

### 🔎 1. Recherche des fichiers appartenant à `flag00` :

```bash
find / -user flag00 2>/dev/null
```

**Résultat :**

```
/usr/sbin/john
/rofs/usr/sbin/john
```

---

### 📄 2. Lecture du fichier suspect :

```bash
cat /usr/sbin/john
```

**Contenu trouvé :**

```
cdiiddwpgswtgt
```

---

### 🧠 3. Déchiffrement du texte

Analyse sur [dcode.fr – ROT Cipher](https://www.dcode.fr/rot-cipher) → déchiffrement en **ROT15**

**Résultat :**
```
nottoohardhere
```

---

### 🔐 4. Connexion avec `su` :

```bash
su flag00
```

💬 **Mot de passe** : `nottoohardhere`

---

### 🏁 5. Récupération du flag :

```bash
getflag
```

**Résultat :**

```
Check flag.Here is your token : x24ti5gi3x0ol2eh4esiuxias
```

---

## ✅ Résumé

- 🔑 Mot de passe `flag00` : `nottoohardhere`  
- 🏆 Token `flag00` : `x24ti5gi3x0ol2eh4esiuxias`
