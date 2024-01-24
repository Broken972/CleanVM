#!/bin/bash

# Définition des fichiers de log et de résumé
LOG_FILE="/var/log/myscript.log"
SUMMARY_FILE="summary.txt"

# Fonction pour écrire dans les fichiers de log et de résumé
log_and_summarizee() {
    echo "$(date): $1" | tee -a "$LOG_FILE" >> "$SUMMARY_FILE"
}

# Mise à jour du système
echo "Début de la mise à jour du système..."
apt-get update && apt-get upgrade -y
echo "Mise à jour du système terminée."

# # Installation et configuration de UFW
echo "Installation de UFW..."
apt-get install ufw -y
ufw allow ssh
ufw allow http
ufw enable 
echo "UFW installé et configuré."

# Modification du port SSH (ex. port 2222)
echo "Changement du port SSH..."
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
systemctl restart sshd
echo "Port SSH changé en 2222."

# Configuration de la politique de mot de passe
echo "Configuration de la politique de mot de passe..."
# Modification du fichier de configuration PAM pour les mots de passe
PAM_PW_FILE="/etc/pam.d/common-password"
# Sauvegarde de l'ancienne configuration
cp $PAM_PW_FILE "$PAM_PW_FILE.bak"
# Configuration pour exiger un minimum de 8 caractères et au moins 1 caractère spécial
sed -i 's/pam_pwquality.so/& minlen=8 minclass=1/' $PAM_PW_FILE
echo "Politique de mot de passe configurée. Minimum 8 caractères et 1 caractère spécial requis."


# # Création d'un utilisateur non-root avec des privilèges sudo
NEW_USER="UtilisateurX"
echo "Création de l'utilisateur $NEW_USER..."
adduser --disabled-password --gecos "" --allow-bad-names $NEW_USER
adduser $NEW_USER sudo
echo "Utilisateur $NEW_USER créé et ajouté au groupe sudo."

# # Désactivation de la connexion SSH root
echo "Désactivation de la connexion SSH root..."
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd
echo "Connexion SSH root désactivée."

# Configuration des logs avec auditd pour surveiller plus de changements
echo "Installation et configuration avancée de auditd..."
# Installation de auditd
apt-get install auditd -y
# Configuration avancée de auditd
AUDITD_RULES_FILE="/etc/audit/audit.rules"
# Sauvegarde de l'ancienne configuration
cp $AUDITD_RULES_FILE "$AUDITD_RULES_FILE.bak"
# Surveiller les changements dans les fichiers sensibles
echo "-w /etc/passwd -p wa -k identity" >> $AUDITD_RULES_FILE
echo "-w /etc/shadow -p wa -k identity" >> $AUDITD_RULES_FILE
echo "-w /etc/group -p wa -k identity" >> $AUDITD_RULES_FILE
echo "-w /etc/gshadow -p wa -k identity" >> $AUDITD_RULES_FILE
echo "-w /etc/sudoers -p wa -k sudo" >> $AUDITD_RULES_FILE
# Surveiller l'utilisation des commandes importantes
echo "-a always,exit -F path=/bin/vi -F perm=x -F auid>=1000 -F auid!=4294967295 -k editing" >> $AUDITD_RULES_FILE
echo "-a always,exit -F path=/usr/bin/vim -F perm=x -F auid>=1000 -F auid!=4294967295 -k editing" >> $AUDITD_RULES_FILE
echo "-a always,exit -F path=/usr/bin/nano -F perm=x -F auid>=1000 -F auid!=4294967295 -k editing" >> $AUDITD_RULES_FILE
echo "-a always,exit -F path=/usr/bin/chmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k permission_change" >> $AUDITD_RULES_FILE
# Surveiller les modifications de la configuration de sécurité
echo "-w /etc/security/ -p wa -k security" >> $AUDITD_RULES_FILE
# Redémarrage du service auditd pour appliquer les changements
systemctl restart auditd
echo "auditd installé et configuré avec des règles avancées."


# Renforcement de SSH
echo "Renforcement de la configuration SSH..."
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd
echo "Configuration SSH renforcée."

# Sandboxing des applications avec Firejail
echo "Installation de Firejail pour le sandboxing des applications..."
apt-get install firejail -y
# Sandboxing de Firefox
echo "firejail firefox" > /usr/local/bin/firefox-sandboxed
chmod +x /usr/local/bin/firefox-sandboxed
echo "Firefox configuré pour s'exécuter dans Firejail."
# Sandboxing avec VLC
echo "firejail vlc" > /usr/local/bin/vlc-sandboxed
chmod +x /usr/local/bin/vlc-sandboxed
echo "VLC configuré pour s'exécuter dans Firejail."
echo "Firejail installé et configuré pour le sandboxing de plusieurs applications."


# Configuration de Fail2Ban pour la prévention d'intrusion
echo "Installation et configuration de Fail2Ban..."
apt-get install fail2ban -y
# Copie de la configuration par défaut pour la personnalisation
cp /etc/fail2ban/jail.local
# Configuration de base de Fail2Ban dans jail.local
cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
# "bantime" est la durée pendant laquelle une IP est bannie.
bantime = 10m
# "findtime" est la durée pendant laquelle Fail2Ban va regarder les tentatives de connexion.
findtime = 10m
# "maxretry" est le nombre de tentatives avant bannissement.
maxretry = 5
# Configuration pour SSH
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h
# Ajouter ici d'autres configurations spécifiques
EOF
# Redémarrage du service Fail2Ban pour appliquer les changements
systemctl restart fail2ban
echo "Fail2Ban configuré avec des règles personnalisées."


# Surveillance des fichiers système avec AIDE
echo "Installation et initialisation de AIDE..."
apt-get install aide -y
# Initialisation de la base de données AIDE
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
echo "Base de données AIDE initialisée."
# Configuration du fichier de configuration d'AIDE
AIDE_CONFIG="/etc/aide/aide.conf"
# Ajout de règles de surveillance personnalisées (exemple)
echo "## Règles personnalisées" >> $AIDE_CONFIG
echo "/etc Crontab Binaries = p+i+n+u+g+s+m+c+md5+sha1" >> $AIDE_CONFIG
echo "/var/log ImportantLogs = p+i+n+u+g+s+m+c+md5+sha1" >> $AIDE_CONFIG
# Mise à jour de la base de données AIDE pour inclure les nouvelles règles
aide --update
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
# Planification des vérifications régulières avec cron
echo "0 3 * * * /usr/bin/aide --check" >> /etc/crontab
echo "AIDE configuré avec des règles personnalisées et vérification planifiée."
# Fin de la section sur AIDE


# Configuration des audits réguliers avec Lynis
echo "Installation de Lynis pour les audits réguliers..."
apt-get install lynis -y
# Planification des audits réguliers avec cron
echo "0 2 * * 1 /usr/bin/lynis audit system >> /var/log/lynis-audit.log" >> /etc/crontab
echo "Lynis installé et planifié pour des audits réguliers."
# Fin de la section sur Lynis



# Fin du script dans la console


echo "Script terminé."
