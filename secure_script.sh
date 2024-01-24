#!/bin/bash

# Définition des fichiers de log et de résumé
LOG_FILE="/var/log/myscript.log"
SUMMARY_FILE="summary.txt"

# Fonction pour écrire dans les fichiers de log et de résumé
log_and_summarize() {
    echo "$(date): $1" | tee -a "$LOG_FILE" >> "$SUMMARY_FILE"
}

# Mise à jour du système
log_and_summarize "Début de la mise à jour du système..."
apt-get update && apt-get upgrade -y
log_and_summarize "Mise à jour du système terminée."

# # Installation et configuration de UFW
log_and_summarize "Installation de UFW..."
apt-get install ufw -y
ufw allow ssh
ufw allow http
ufw enable -y
log_and_summarize "UFW installé et configuré."

# # Modification du port SSH (ex. port 2222)
# log_and_summarize "Changement du port SSH..."
# sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
# systemctl restart sshd
# log_and_summarize "Port SSH changé en 2222."

# # Configuration de la politique de mot de passe
# log_and_summarize "Configuration de la politique de mot de passe..."
# # Modification du fichier de configuration PAM pour les mots de passe
# PAM_PW_FILE="/etc/pam.d/common-password"
# # Sauvegarde de l'ancienne configuration
# cp $PAM_PW_FILE "$PAM_PW_FILE.bak"
# # Configuration pour exiger un minimum de 8 caractères et au moins 1 caractère spécial
# sed -i 's/pam_pwquality.so/& minlen=8 minclass=1/' $PAM_PW_FILE
# log_and_summarize "Politique de mot de passe configurée. Minimum 8 caractères et 1 caractère spécial requis."


# # Création d'un utilisateur non-root avec des privilèges sudo
# NEW_USER="UtilisateurX"
# log_and_summarize "Création de l'utilisateur $NEW_USER..."
# adduser --disabled-password --gecos "" $NEW_USER
# adduser $NEW_USER sudo
# log_and_summarize "Utilisateur $NEW_USER créé et ajouté au groupe sudo."

# # Désactivation de la connexion SSH root
# log_and_summarize "Désactivation de la connexion SSH root..."
# sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
# systemctl restart sshd
# log_and_summarize "Connexion SSH root désactivée."

# # Configuration des logs avec auditd pour surveiller plus de changements
# log_and_summarize "Installation et configuration avancée de auditd..."
# # Installation de auditd
# apt-get install auditd -y
# # Configuration avancée de auditd
# AUDITD_RULES_FILE="/etc/audit/audit.rules"
# # Sauvegarde de l'ancienne configuration
# cp $AUDITD_RULES_FILE "$AUDITD_RULES_FILE.bak"
# # Surveiller les changements dans les fichiers sensibles
# echo "-w /etc/passwd -p wa -k identity" >> $AUDITD_RULES_FILE
# echo "-w /etc/shadow -p wa -k identity" >> $AUDITD_RULES_FILE
# echo "-w /etc/group -p wa -k identity" >> $AUDITD_RULES_FILE
# echo "-w /etc/gshadow -p wa -k identity" >> $AUDITD_RULES_FILE
# echo "-w /etc/sudoers -p wa -k sudo" >> $AUDITD_RULES_FILE
# # Surveiller l'utilisation des commandes importantes
# echo "-a always,exit -F path=/bin/vi -F perm=x -F auid>=1000 -F auid!=4294967295 -k editing" >> $AUDITD_RULES_FILE
# echo "-a always,exit -F path=/usr/bin/vim -F perm=x -F auid>=1000 -F auid!=4294967295 -k editing" >> $AUDITD_RULES_FILE
# echo "-a always,exit -F path=/usr/bin/nano -F perm=x -F auid>=1000 -F auid!=4294967295 -k editing" >> $AUDITD_RULES_FILE
# echo "-a always,exit -F path=/usr/bin/chmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k permission_change" >> $AUDITD_RULES_FILE
# # Surveiller les modifications de la configuration de sécurité
# echo "-w /etc/security/ -p wa -k security" >> $AUDITD_RULES_FILE
# # Redémarrage du service auditd pour appliquer les changements
# systemctl restart auditd
# log_and_summarize "auditd installé et configuré avec des règles avancées."


# # Configuration avancée de SELinux pour d'autres aspects du système
# log_and_summarize "Début de la configuration avancée de SELinux pour des aspects non-web..."
# # Activer SELinux en mode Enforcing
# sed -i 's/SELINUX=.*$/SELINUX=enforcing/' /etc/selinux/config
# setenforce 1
# log_and_summarize "SELinux mis en mode Enforcing."
# # Sécurisation des services d'authentification
# # Configurer SELinux pour surveiller les accès au service SSH
# semanage fcontext -a -t sshd_etc_t "/etc/ssh/sshd_config"
# restorecon -v /etc/ssh/sshd_config
# # Gestion des accès utilisateurs
# # Définir des politiques pour limiter l'accès utilisateur à certains dossiers
# semanage fcontext -a -t user_home_dir_t "/home/restricted_user(/.*)?"
# restorecon -R /home/restricted_user
# # Sécurisation des fichiers de configuration système
# # Appliquer un contexte de sécurité aux fichiers de configuration de réseau
# semanage fcontext -a -t etc_t "/etc/sysconfig/network(/.*)?"
# restorecon -R /etc/sysconfig/network
# # Configuration des booléens SELinux pour des services spécifiques
# # Empêcher les utilisateurs non privilégiés de mapper la mémoire dans d'autres processus
# setsebool -P allow_ptrace 0
# # Vérification de la configuration
# sestatus
# log_and_summarize "Configuration avancée de SELinux pour des aspects non-web terminée."


# # Intégration d'un système de détection d'intrusion (Snort)
# log_and_summarize "Installation du système de détection d'intrusion Snort..."
# # Installation de Snort
# apt-get install snort -y
# # Configuration de base de Snort
# SNORT_CONFIG="/etc/snort/snort.conf"
# # Sauvegarde de la configuration d'origine
# cp $SNORT_CONFIG "$SNORT_CONFIG.bak"
# # Configuration de l'interface réseau (à remplacer par l'interface appropriée)
# sed -i 's/ipvar HOME_NET any/ipvar HOME_NET [127.0.0.1\/255.255.255.0]/' $SNORT_CONFIG
# # Téléchargement des règles de détection 
# snort-rules-update
# # Vérification de la configuration Snort
# snort -T -c $SNORT_CONFIG
# log_and_summarize "Snort installé et configuré."

# # Renforcement de SSH
# log_and_summarize "Renforcement de la configuration SSH..."
# sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
# sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
# systemctl restart sshd
# log_and_summarize "Configuration SSH renforcée."

# # Sandboxing des applications avec Firejail
# log_and_summarize "Installation de Firejail pour le sandboxing des applications..."
# apt-get install firejail -y
# # Sandboxing de Firefox
# echo "firejail firefox" > /usr/local/bin/firefox-sandboxed
# chmod +x /usr/local/bin/firefox-sandboxed
# log_and_summarize "Firefox configuré pour s'exécuter dans Firejail."
# # Sandboxing avec VLC
# echo "firejail vlc" > /usr/local/bin/vlc-sandboxed
# chmod +x /usr/local/bin/vlc-sandboxed
# log_and_summarize "VLC configuré pour s'exécuter dans Firejail."
# log_and_summarize "Firejail installé et configuré pour le sandboxing de plusieurs applications."


# # Configuration de Fail2Ban pour la prévention d'intrusion
# log_and_summarize "Installation et configuration de Fail2Ban..."
# apt-get install fail2ban -y
# # Copie de la configuration par défaut pour la personnalisation
# cp /etc/fail2ban/jail.{conf,local}
# # Configuration de base de Fail2Ban dans jail.local
# cat << EOF > /etc/fail2ban/jail.local
# [DEFAULT]
# # "bantime" est la durée pendant laquelle une IP est bannie.
# bantime = 10m
# # "findtime" est la durée pendant laquelle Fail2Ban va regarder les tentatives de connexion.
# findtime = 10m
# # "maxretry" est le nombre de tentatives avant bannissement.
# maxretry = 5
# # Configuration pour SSH
# [sshd]
# enabled = true
# port = ssh
# filter = sshd
# logpath = /var/log/auth.log
# maxretry = 3
# bantime = 1h
# # Ajouter ici d'autres configurations spécifiques
# EOF
# # Redémarrage du service Fail2Ban pour appliquer les changements
# systemctl restart fail2ban
# log_and_summarize "Fail2Ban configuré avec des règles personnalisées."


# # Surveillance des fichiers système avec AIDE
# log_and_summarize "Installation et initialisation de AIDE..."
# apt-get install aide -y
# # Initialisation de la base de données AIDE
# aideinit
# mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
# log_and_summarize "Base de données AIDE initialisée."
# # Configuration du fichier de configuration d'AIDE
# AIDE_CONFIG="/etc/aide/aide.conf"
# # Ajout de règles de surveillance personnalisées (exemple)
# echo "## Règles personnalisées" >> $AIDE_CONFIG
# echo "/etc Crontab Binaries = p+i+n+u+g+s+m+c+md5+sha1" >> $AIDE_CONFIG
# echo "/var/log ImportantLogs = p+i+n+u+g+s+m+c+md5+sha1" >> $AIDE_CONFIG
# # Mise à jour de la base de données AIDE pour inclure les nouvelles règles
# aide --update
# mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
# # Planification des vérifications régulières avec cron
# echo "0 3 * * * /usr/bin/aide --check" >> /etc/crontab
# log_and_summarize "AIDE configuré avec des règles personnalisées et vérification planifiée."
# # Fin de la section sur AIDE


# # Configuration des audits réguliers avec Lynis
# log_and_summarize "Installation de Lynis pour les audits réguliers..."
# apt-get install lynis -y
# # Planification des audits réguliers avec cron
# echo "0 2 * * 1 /usr/bin/lynis audit system >> /var/log/lynis-audit.log" >> /etc/crontab
# log_and_summarize "Lynis installé et planifié pour des audits réguliers."
# # Fin de la section sur Lynis


# # Fin du script
# log_and_summarize "Script terminé."
