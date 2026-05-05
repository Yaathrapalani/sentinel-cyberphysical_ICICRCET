
# Paths
DATA_RAW = "data/raw/BATADAL_dataset03.csv"
DATA_PROCESSED = "data/processed/"
MODEL_SAVED    = "models/saved/"

# Federated learning
NUM_ROUNDS     = 5
NUM_CLIENTS    = 3
MIN_CLIENTS    = 2

# Differential privacy
EPSILON        = 0.5
DELTA          = 1e-5
NOISE_MULT     = 1.1
MAX_GRAD_NORM  = 1.0

# Krum
BYZANTINE_TOLERANCE = 1      # tolerate 1 malicious client out of 3

# Correlation engine
WINDOW_SIZE    = 20          # timesteps in rolling window
NORMAL_THRESH  = 0.7         # correlation above this = normal
CRITICAL_THRESH = 0.3        # correlation below this = compound attack

# Dashboard
REFRESH_RATE   = 2           # seconds between dashboard updates
ALERT_HISTORY  = 50          # number of alerts to keep in log

# Attack simulation
ATTACK_START   = 200         # timestep where attack begins
ATTACK_DURATION = 50         # how long attack lasts
SPOOF_VALUE    = 0.05        # fake "normal" physical score during attack