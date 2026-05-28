# train.py — Entrainement sur donnees reelles uniquement
# Aucune donnee synthetique
# Lance : python train.py

import pandas as pd
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser   import parser_logs, detecter_comportements
from features import FEATURES, auto_label, entrainer_modele

print("=" * 55)
print("  LOGSENTINEL — Entrainement donnees reelles")
print("=" * 55)

FICHIER = 'logs_simulation_bruts.csv'

if not os.path.exists(FICHIER):
    print(f"\nERREUR : {FICHIER} introuvable.")
    print(f"Place ton fichier dans ce dossier.")
    sys.exit(1)

# ── 1. Parser les logs bruts ─────────────────────────────────
print(f"\nChargement : {FICHIER}")
df_logs       = parser_logs(FICHIER)
comportements = detecter_comportements(df_logs)

if not comportements:
    print("Aucune session detectee — verifie ton fichier.")
    sys.exit(1)

# ── 2. Construire le dataset features ───────────────────────
df = pd.DataFrame(comportements)

# Assurer que toutes les features existent
for col in FEATURES:
    if col not in df.columns:
        df[col] = 0

# Générer les labels Y automatiquement
df['label'] = df.apply(auto_label, axis=1)

# Sauvegarder pour inspection
df_save = df[FEATURES + ['label','comportement','fenetre']].copy()
df_save.to_csv('dataset_features.csv', index=False)

# ── 3. Afficher le bilan ─────────────────────────────────────
noms = {0:'FAIBLE', 1:'MODERE', 2:'ELEVE', 3:'CRITIQUE'}
print("\nDataset construit :")
print(f"  Sessions totales  : {len(df)}")
print(f"\nDistribution labels :")
for k, v in df['label'].value_counts().sort_index().items():
    barre = '█' * v
    print(f"  {noms[k]:<10} {barre} ({v})")

print("\nDetail des sessions suspectes :")
suspects = df[df['comportement'] != 'NORMAL']
for _, r in suspects.iterrows():
    print(f"  {r['comportement']:<25} "
          f"heure={r['heure']}h  "
          f"echecs={r['nb_echecs']}  "
          f"label={noms[r['label']]}")

# ── 4. Vérifier si entraînable ───────────────────────────────
nb_classes = df['label'].nunique()
nb_total   = len(df)

if nb_classes < 2:
    print(f"\nATTENTION : Seulement {nb_classes} classe(s) detectee(s).")
    print("Le modele a besoin d au moins 2 classes.")
    print("Genere des logs avec plus de variete.")
    sys.exit(1)

min_par_classe = df['label'].value_counts().min()
if min_par_classe < 2:
    print(f"\nATTENTION : Certaines classes ont moins de 2 exemples.")
    print("Les resultats peuvent ne pas etre fiables.")

# ── 5. Entrainer le modele ───────────────────────────────────
print("\nEntrainement en cours...")
modele = entrainer_modele(df=df[FEATURES + ['label']], sauvegarder=True)

print("\n" + "=" * 55)
print("  model_logs.pkl genere !")
print("  dataset_features.csv sauvegarde")
print("  Lance : streamlit run app.py")
print("=" * 55)
