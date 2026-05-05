import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import os
from utils.config import DATA_RAW, DATA_PROCESSED

# BATADAL column classification
# Physical sensors: flow meters (F), pressure (P), tank levels (L)
# Cyber/actuator signals: pump status (S), control commands
PHYSICAL_COLS = [
    'L_T1', 'L_T2', 'L_T3', 'L_T4', 'L_T5', 'L_T6', 'L_T7',
    'F_PU1', 'F_PU2', 'F_PU3', 'F_PU4', 'F_PU5', 'F_PU6',
    'F_PU7', 'F_PU8', 'F_PU9', 'F_PU10', 'F_PU11',
    'P_J280', 'P_J269', 'P_J300', 'P_J256', 'P_J289',
    'P_J415', 'P_J302', 'P_J306', 'P_J307', 'P_J317', 'P_J14', 'P_J422'
]

CYBER_COLS = [
    'S_PU1', 'S_PU2', 'S_PU3', 'S_PU4', 'S_PU5', 'S_PU6',
    'S_PU7', 'S_PU8', 'S_PU9', 'S_PU10', 'S_PU11',
    'S_V2'
]


def load_batadal(path=DATA_RAW):
    """Load BATADAL CSV and parse timestamps."""
    print(f"[Preprocessor] Loading dataset from {path}")
    df = pd.read_csv(path, sep=';', skipinitialspace=True)

    # Normalize column names: strip whitespace
    df.columns = [c.strip() for c in df.columns]

    # Parse datetime
    # NEW — correct separator and correct datetime format
    df = pd.read_csv(path, sep=',', skipinitialspace=True)
    df['DATETIME'] = pd.to_datetime(df['DATETIME'], format='%d/%m/%y %H')

    print(f"[Preprocessor] Loaded {len(df)} rows | "
          f"Columns: {len(df.columns)} | "
          f"Range: {df['DATETIME'].min()} to {df['DATETIME'].max()}")
    return df


def validate_columns(df):
    """Check that expected columns exist. Warn if missing."""
    missing_phys = [c for c in PHYSICAL_COLS if c not in df.columns]
    missing_cyber = [c for c in CYBER_COLS if c not in df.columns]

    if missing_phys:
        print(f"[WARNING] Missing physical columns: {missing_phys}")
    if missing_cyber:
        print(f"[WARNING] Missing cyber columns: {missing_cyber}")

    # Use only columns that actually exist
    phys = [c for c in PHYSICAL_COLS if c in df.columns]
    cyber = [c for c in CYBER_COLS if c in df.columns]
    return phys, cyber


def scale_features(df, cols):
    """MinMax scale selected columns. Returns scaled array + fitted scaler."""
    scaler = MinMaxScaler()
    scaled = scaler.fit_transform(df[cols].fillna(0))
    return scaled, scaler


def split_into_nodes(df, phys_cols, cyber_cols):
    """
    Split dataset into 3 node subsets simulating 3 infrastructure sites.
    We split chronologically so each node sees a different time window.
    This simulates heterogeneous data across sites (non-IID distribution).
    """
    n = len(df)
    split_a = int(n * 0.40)
    split_b = int(n * 0.70)

    nodes = {
        'node_a': df.iloc[:split_a].copy(),          # 40% — power grid sim
        'node_b': df.iloc[split_a:split_b].copy(),   # 30% — water treatment sim
        'node_c': df.iloc[split_b:].copy(),           # 30% — transport sim
    }

    print(f"[Preprocessor] Node split sizes: "
          f"A={len(nodes['node_a'])} | "
          f"B={len(nodes['node_b'])} | "
          f"C={len(nodes['node_c'])}")

    return nodes


def prepare_node_features(node_df, phys_cols, cyber_cols):
    """
    For a single node dataframe, return:
    - X_physical: scaled physical sensor array
    - X_cyber: scaled cyber/actuator array
    - X_combined: concatenated for joint model training
    - timestamps: aligned datetime index
    """
    phys_scaled, phys_scaler = scale_features(node_df, phys_cols)
    cyber_scaled, cyber_scaler = scale_features(node_df, cyber_cols)

    X_combined = np.hstack([phys_scaled, cyber_scaled])
    timestamps = node_df['DATETIME'].values

    return {
        'X_physical': phys_scaled,
        'X_cyber': cyber_scaled,
        'X_combined': X_combined,
        'timestamps': timestamps,
        'phys_scaler': phys_scaler,
        'cyber_scaler': cyber_scaler,
        'phys_cols': phys_cols,
        'cyber_cols': cyber_cols,
    }


def run_preprocessing():
    """Full pipeline: load → validate → split → save processed files."""
    os.makedirs(DATA_PROCESSED, exist_ok=True)

    df = load_batadal()
    phys_cols, cyber_cols = validate_columns(df)
    nodes = split_into_nodes(df, phys_cols, cyber_cols)

    processed = {}
    for name, node_df in nodes.items():
        features = prepare_node_features(node_df, phys_cols, cyber_cols)
        processed[name] = features

        # Save raw node CSV for reference
        save_path = os.path.join(DATA_PROCESSED, f"{name}.csv")
        node_df.to_csv(save_path, index=False)
        print(f"[Preprocessor] Saved {name} → {save_path}")

    print("[Preprocessor] All nodes preprocessed successfully.")
    return processed, phys_cols, cyber_cols


if __name__ == "__main__":
    run_preprocessing()