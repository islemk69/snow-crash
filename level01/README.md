# Snow Crash – Level01

## 🔍 Objectif  
Accéder au compte `flag01` en cassant un mot de passe chiffré trouvé dans `/etc/passwd` grâce à John the Ripper, puis récupérer le token avec `getflag`.

---

## 🧾 Étapes réalisées

### 📂 1. Lecture du fichier `/etc/passwd` :

```bash
cat /etc/passwd
```

**Résultat :**

```
flag00:x:3000:3000::/home/flag/flag00:/bin/bash
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
```

On identifie ici que `42hDRfypTqqnw` est le mot de passe chiffré du compte `flag01`.

---

### 🛠️ 2. Préparation de l’environnement John the Ripper

#### 📦 Installation des dépendances (si besoin) :

```bash
sudo apt install -y build-essential libssl-dev git yasm
```

#### 🔽 Compilation de John the Ripper :

```bash
cd level01/ressources/john/src
./configure
make -s clean
make -sj8
```

#### 🚀 Accès au binaire compilé :

```bash
cd ../run
```

---

### 🔐 3. Cassage du mot de passe avec John

#### 📝 Création du fichier contenant le hash :

```bash
echo "flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash" > pass
```

#### 🔓 Lancement de John :

```bash
./john pass
./john pass --show
```

**Résultat :**

```
?:abcdefg
1 password hash cracked, 0 left
```

---

### 🔑 4. Connexion avec `su` :

```bash
su flag01
```

💬 **Mot de passe** : `abcdefg`

---

### 🏁 5. Récupération du flag :

```bash
getflag
```

**Résultat :**

```
Check flag.Here is your token : f2av5il02puano7naaf6adaaf
```

---

## ✅ Résumé

- 🔑 Mot de passe `flag01` : `abcdefg`  
- 🏆 Token `flag01` : `f2av5il02puano7naaf6adaaf`  
- 🔑 Mot de passe pour `level02` : `f2av5il02puano7naaf6adaaf`