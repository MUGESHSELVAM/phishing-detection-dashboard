import pandas as pd
from sklearn.model_selection import train_test_split


# Basic preprocessing for URL dataset

def load_dataset(csv_path: str) -> pd.DataFrame:
    """Load the phishing dataset CSV into a DataFrame."""
    df = pd.read_csv(csv_path)
    return df


def split_dataset(df: pd.DataFrame, test_size: float = 0.2, random_state: int = 42):
    """Split into training and test sets."""
    X = df.drop("label", axis=1)
    y = df["label"]
    return train_test_split(X, y, test_size=test_size, random_state=random_state)
