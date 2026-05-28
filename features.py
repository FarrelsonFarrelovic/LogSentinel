import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score

# ─────────────────────────────────────────────────────────────
# FEATURES — adaptées aux nouveaux Event IDs
# ─────────────────────────────────────────────────────────────
FEATURES = [
    'nb_echecs',
    'nb_succes',
    'nb_ip_dist',
    'privilege_eleve',
    'nb_powershell',
    'nb_comptes_crees',
    'nb_processus',
    'hors_horaires',
    'heure',
    'nb_total_events',
    'nb_enum',
    'nb_creds',
    'cvss',
    'epss',
]

NOMS_FEATURES = {
    'nb_echecs'       : 'Echecs de connexion',
    'nb_succes'       : 'Connexions reussies',
    'nb_ip_dist'      : 'IP sources distinctes',
    'privilege_eleve' : 'Privileges eleves',
    'nb_powershell'   : 'Scripts PowerShell',
    'nb_comptes_crees': 'Comptes crees',
    'nb_processus'    : 'Processus lances',
    'hors_horaires'   : 'Activite hors horaires',
    'heure'           : 'Heure de l activite',
    'nb_total_events' : 'Total evenements',
    'nb_enum'         : 'Enumeration comptes',
    'nb_creds'        : 'Lecture credentials',
    'cvss'            : 'Score CVSS CVE',
    'epss'            : 'Score EPSS CVE',
}

NIVEAUX = {
    0: ('FAIBLE',   '#27ae60'),
    1: ('MODERE',   '#f39c12'),
    2: ('ELEVE',    '#e67e22'),
    3: ('CRITIQUE', '#e74c3c'),
}


def extraire_features(comportement):
    return pd.DataFrame([{f: comportement.get(f, 0) for f in FEATURES}])


def auto_label(row):
    """
    Labellisation par score pondéré.
    Adapté aux comportements présents dans les logs réels.
    """
    score = 0

    # Echecs connexion (bruteforce)
    if   row['nb_echecs'] >= 20: score += 45
    elif row['nb_echecs'] >= 10: score += 30
    elif row['nb_echecs'] >= 5:  score += 18
    elif row['nb_echecs'] >= 2:  score += 8

    # Hors horaires
    if row['hors_horaires'] == 1: score += 20
    if row['heure'] <= 5:         score += 10

    # Privileges élevés
    if   row['privilege_eleve'] >= 15: score += 20
    elif row['privilege_eleve'] >= 8:  score += 12
    elif row['privilege_eleve'] >= 3:  score += 6

    # Compte créé
    if row['nb_comptes_crees'] >= 1: score += 15

    # Enumération de comptes (nouveaux Event IDs)
    if   row['nb_enum'] >= 100: score += 20
    elif row['nb_enum'] >= 30:  score += 12
    elif row['nb_enum'] >= 10:  score += 6

    # Lecture credentials (nouveaux Event IDs)
    if   row['nb_creds'] >= 20: score += 18
    elif row['nb_creds'] >= 5:  score += 10
    elif row['nb_creds'] >= 1:  score += 4

    # EPSS
    if   row['epss'] >= 0.90: score += 12
    elif row['epss'] >= 0.50: score += 6

    # Label final
    if score >= 55: return 3   # CRITIQUE
    if score >= 30: return 2   # ELEVE
    if score >= 12: return 1   # MODERE
    return 0                   # FAIBLE


def entrainer_modele(df, sauvegarder=True):
    """
    Entraîne le Random Forest sur le dataset fourni.
    Pas de données synthétiques — uniquement les données réelles.
    """
    X = df[FEATURES]
    y = df['label']

    nb_classes = y.nunique()
    nb_total   = len(df)

    print(f"[TRAIN] {nb_total} sessions | {nb_classes} classes")

    # Paramètres adaptés à la taille du dataset
    if nb_total >= 50:
        test_size = 0.2
        params    = dict(
            n_estimators   = 100,
            max_depth      = 8,
            min_samples_split = 5,
            min_samples_leaf  = 2,
            max_features   = 'sqrt',
            random_state   = 42,
            class_weight   = 'balanced'
        )
    else:
        # Petit dataset — paramètres plus souples
        test_size = 0.15
        params    = dict(
            n_estimators   = 50,
            max_depth      = 5,
            min_samples_split = 2,
            min_samples_leaf  = 1,
            max_features   = 'sqrt',
            random_state   = 42,
            class_weight   = 'balanced'
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )

    model = RandomForestClassifier(**params)
    model.fit(X_train, y_train)

    # Evaluation
    y_pred    = model.predict(X_test)
    acc_test  = accuracy_score(y_test, y_pred)
    acc_train = accuracy_score(y_train, model.predict(X_train))
    gap       = acc_train - acc_test

    print(f"\n[TRAIN] Accuracy test  : {acc_test:.2%}")
    print(f"[TRAIN] Accuracy train : {acc_train:.2%}")
    print(f"[TRAIN] Gap train/test : {gap:.2%} "
          f"({'OK' if gap < 0.10 else 'ATTENTION overfitting'})")

    # Cross-validation si assez de données
    if nb_total >= 30:
        cv  = min(5, nb_classes * 2)
        cvs = cross_val_score(model, X, y, cv=cv)
        print(f"[TRAIN] Cross-val {cv}-folds : "
              f"{cvs.mean():.2%} (+/- {cvs.std():.2%})")

    # Noms des classes présentes
    classes_presentes = [
        {0:'FAIBLE',1:'MODERE',2:'ELEVE',3:'CRITIQUE'}[c]
        for c in sorted(y.unique())
    ]
    print("\n" + classification_report(
        y_test, y_pred,
        labels=sorted(y_test.unique()), target_names=classes_presentes
    ))

    if sauvegarder:
        joblib.dump(model,    'model_logs.pkl')
        joblib.dump(FEATURES, 'features.pkl')
        print("[TRAIN] model_logs.pkl sauvegarde ✅")

    return model


def charger_modele():
    import os
    if not os.path.exists('model_logs.pkl'):
        print("[MODEL] model_logs.pkl introuvable.")
        print("[MODEL] Lance d abord : python train.py")
        raise FileNotFoundError("model_logs.pkl absent — lance train.py d abord")
    return joblib.load('model_logs.pkl')


def predire(comportement, model):
    X      = extraire_features(comportement)
    proba  = model.predict_proba(X)[0]
    label  = model.predict(X)[0]

    # Score = probabilité de la classe la plus grave présente
    classes = model.classes_
    if 3 in classes:
        idx_crit = list(classes).index(3)
        score    = round(float(proba[idx_crit]) * 100, 1)
    else:
        score = round(float(proba.max()) * 100, 1)

    niveau = NIVEAUX[label]

    # Feature importance LOCALE — pondérée par les valeurs de cette alerte
    valeurs       = X.values[0]
    imp_globale   = model.feature_importances_
    valeurs_norm  = valeurs / (valeurs.sum() + 1e-9)
    imp_locale    = imp_globale * (1 + valeurs_norm)
    imp_locale    = imp_locale  / imp_locale.sum()

    importances = dict(zip(
        [NOMS_FEATURES.get(f, f) for f in FEATURES],
        imp_locale
    ))

    # Probas sur les 4 classes (mettre 0 si classe absente)
    probas_dict = {'FAIBLE':0.0,'MODERE':0.0,'ELEVE':0.0,'CRITIQUE':0.0}
    nom_classe  = {0:'FAIBLE',1:'MODERE',2:'ELEVE',3:'CRITIQUE'}
    for i, c in enumerate(classes):
        probas_dict[nom_classe[c]] = round(float(proba[i])*100, 1)

    return {
        'score'      : score,
        'label'      : int(label),
        'niveau'     : niveau[0],
        'couleur'    : niveau[1],
        'probas'     : probas_dict,
        'importances': dict(sorted(
            importances.items(), key=lambda x: x[1], reverse=True
        ))
    }
