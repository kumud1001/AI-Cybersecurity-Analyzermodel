import os
import pandas as pd
import matplotlib.pyplot as plt


DATASET = "data/processed/cicids2017_cleaned.csv"

FIGURES_DIR = "experiments/figures"
RESULTS_DIR = "experiments/results"


def load_data():

    print("Loading dataset...")

    df = pd.read_csv(
        DATASET,
        low_memory=False
    )

    print("\nDataset loaded successfully.")

    print("Rows:", len(df))
    print("Columns:", len(df.columns))

    return df


def dataset_information(df):

    print("\n========================================")
    print("DATASET INFORMATION")
    print("========================================")

    print("Rows:", len(df))
    print("Columns:", len(df.columns))

    print("\nData types:")

    print(
        df.dtypes.value_counts()
    )


def missing_value_analysis(df):

    print("\n========================================")
    print("MISSING VALUE ANALYSIS")
    print("========================================")

    missing = (
        df.isnull()
        .sum()
        .sort_values(
            ascending=False
        )
    )

    missing = missing[
        missing > 0
    ]

    if len(missing) == 0:

        print(
            "No missing values found."
        )

    else:

        print(missing)


def attack_distribution(df):

    print("\n========================================")
    print("ATTACK DISTRIBUTION")
    print("========================================")

    counts = (
        df["label"]
        .value_counts()
    )

    print(counts)

    percentages = (
        df["label"]
        .value_counts(
            normalize=True
        )
        * 100
    )

    result = pd.DataFrame({
        "count": counts,
        "percentage": percentages
    })

    print("\nAttack percentages:")

    print(result)

    os.makedirs(
        RESULTS_DIR,
        exist_ok=True
    )

    result.to_csv(
        f"{RESULTS_DIR}/attack_distribution.csv"
    )

    return counts


def create_attack_graph(counts):

    os.makedirs(
        FIGURES_DIR,
        exist_ok=True
    )

    plt.figure(
        figsize=(12, 7)
    )

    counts.sort_values().plot(
        kind="barh"
    )

    plt.title(
        "CIC-IDS2017 Attack Distribution"
    )

    plt.xlabel(
        "Number of Network Flows"
    )

    plt.ylabel(
        "Attack Type"
    )

    plt.tight_layout()

    output = (
        f"{FIGURES_DIR}/"
        "attack_distribution.png"
    )

    plt.savefig(
        output,
        dpi=300
    )

    plt.close()

    print(
        "\nGraph saved:"
    )

    print(output)


def feature_statistics(df):

    print("\n========================================")
    print("FEATURE STATISTICS")
    print("========================================")

    numeric_df = df.select_dtypes(
        include="number"
    )

    statistics = (
        numeric_df.describe()
    )

    print(statistics)

    statistics.to_csv(
        f"{RESULTS_DIR}/"
        "feature_statistics.csv"
    )

    print(
        "\nFeature statistics saved."
    )


def main():

    print(
        "========================================"
    )

    print(
        " CIC-IDS2017 EXPLORATORY DATA ANALYSIS"
    )

    print(
        "========================================"
    )

    df = load_data()

    dataset_information(df)

    missing_value_analysis(df)

    counts = attack_distribution(df)

    create_attack_graph(counts)

    feature_statistics(df)

    print(
        "\n========================================"
    )

    print(
        " EDA COMPLETED"
    )

    print(
        "========================================"


    )


if __name__ == "__main__":
    main()