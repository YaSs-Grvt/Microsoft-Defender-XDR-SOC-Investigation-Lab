# Microsoft Defender XDR SOC Investigation Lab

Ce dépôt présente un lab d’investigation SOC basé sur Microsoft Defender XDR.  
Il regroupe une documentation méthodologique ainsi qu’un script PowerShell permettant de générer des événements de sécurité contrôlés dans un environnement de test.

L’objectif du projet est de reproduire une situation proche d’un contexte SOC : générer des alertes, analyser les incidents dans Microsoft Defender XDR, étudier la timeline, identifier les entités impactées et documenter une investigation de manière structurée.

---

## Objectif du projet

Ce projet a été réalisé dans le cadre de mon stage chez Exakis Nelite, autour de la détection, de l’analyse et de l’investigation d’incidents de sécurité avec Microsoft Defender XDR.

L’objectif n’est pas simplement de générer des alertes, mais surtout de comprendre comment les analyser correctement :

- identifier les signaux suspects ;
- replacer chaque événement dans son contexte ;
- analyser les processus, fichiers, utilisateurs et connexions réseau ;
- exploiter la timeline de Microsoft Defender XDR ;
- comprendre l’Attack Story ;
- associer certains comportements aux tactiques MITRE ATT&CK ;
- distinguer un vrai signal d’un faux positif ;
- rédiger une conclusion d’investigation claire.

---

## Contenu du dépôt

```text
.
├── docs/
│   └── Methodologie_Investigation_SOC_Defender_XDR.pdf
│
├── scripts/
│   └── Invoke-DefenderXDR-Lab.ps1
│
└── README.md
