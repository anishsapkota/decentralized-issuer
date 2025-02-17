import time
import os
import csv

import numpy as np
import requests
import concurrent.futures
from datetime import datetime
import statistics
import matplotlib.pyplot as plt
import pandas as pd
from typing import Dict, List
from container_manager import ContainerManager as ServerManager
class PerformanceTester:
    def __init__(self, url: str, payload: Dict, max_workers: int = 100):
        self.url = url
        self.payload = payload
        self.max_workers = max_workers
        self.reset_metrics()

    def reset_metrics(self):
        self.response_times = []
        self.success_count = 0
        self.error_counts = {}

    def send_request(self, index: int):
        start_time = time.time()
        try:
            response = requests.post(self.url, json=self.payload, timeout=10)
            elapsed_time = time.time() - start_time
            self.response_times.append(elapsed_time)

            if response.status_code == 200:
                self.success_count += 1
                return True, elapsed_time
            else:
                error_key = f"HTTP {response.status_code}"
                self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
                return False, elapsed_time

        except requests.exceptions.Timeout:
            self.error_counts["Timeout"] = self.error_counts.get("Timeout", 0) + 1
            return False, None
        except requests.exceptions.ConnectionError:
            self.error_counts["Connection Error"] = self.error_counts.get("Connection Error", 0) + 1
            return False, None
        except Exception as e:
            error_type = type(e).__name__
            self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
            return False, None

    def run_test(self, num_requests: int) -> Dict:
        print(f"\nRunning test with {num_requests} requests")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        self.reset_metrics()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, num_requests)) as executor:
            futures = [executor.submit(self.send_request, i) for i in range(num_requests)]
            for future in concurrent.futures.as_completed(futures):
                future.result()  # We already track metrics in the class

        total_requests = num_requests
        success_rate = (self.success_count / total_requests) * 100 if total_requests > 0 else 0
        avg_response = statistics.mean(self.response_times) if self.response_times else 0
        throughput = self.success_count / avg_response if avg_response > 0 else 0

        return {
            "avg_response_time": avg_response,
            "throughput": throughput,
            "error_rate": 100 - success_rate,
            "total_time": sum(self.response_times),
            "success_rate": success_rate,
        }


def check_keys_and_restart(server_manager: ServerManager, n: int, t: int, max_retries: int = 3) -> bool:
    for attempt in range(max_retries):
        try:
            # Count generated key files
            key_files = [f for f in os.listdir(server_manager.keys_dir) if f.endswith(".txt")]
            if len(key_files) == n:
                print(f"Successfully generated {n} keys.")
                return True
            print(f"Key count mismatch. Expected {n}, found {len(key_files)}. Attempt {attempt + 1}/{max_retries}")
        except FileNotFoundError:
            print(f"Keys directory not found: {server_manager.keys_dir}")

        # Restart server if keys are missing
        server_manager.stop_servers(n)
        time.sleep(10)
        if not server_manager.start_servers(n, t):
            return False
        time.sleep(60)  # Wait for server initialization

    print(f"Failed to generate keys after {max_retries} attempts")
    return False


def run_batch_tests_with_repeatition(
        keys_dir: str,
        docker_image_name: str,
        container_name: str,
        network_name: str,
        cleanup_script: str,
        nginx_config_path: str ,
        url: str,
        payload: Dict,
        num_requests: int,
        thresholds: List[int],
        n: int,
        mode:str,
        num_commitments: int,
):
    server_manager = ServerManager(keys_dir, docker_image_name, network_name, cleanup_script,nginx_config_path,mode,num_commitments)
    tester = PerformanceTester(url, payload)
    model = "centralized" if n == 1 and thresholds[0] == 1 else "decentralized"
    with open(f"c-vs-d-test-results/test_results_{model}.csv", "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=[
            "N", "Threshold", "Avg Response Time (s)", "Throughput (req/s)",
            "Error Rate (%)", "Total Time (s)", "Success Rate (%)", "mode"
        ])

        # Write header only if the file is empty
        if csvfile.tell() == 0:
            writer.writeheader()

        for t in thresholds:
            print(f"\n=== Testing threshold T={t} ===")
            server_manager.start_containers(n, t)
            time.sleep(60)  # Initial startup wait

            if not check_keys_and_restart(server_manager, n, t):
                print(f"Skipping threshold {t} due to key generation issues")
                continue

            # Run 15 test iterations
            metrics = {key: [] for key in
                       ["avg_response_time", "throughput", "error_rate", "total_time", "success_rate"]}
            for iteration in range(15):
                try:
                    result = tester.run_test(num_requests)
                    if iteration <= 3:  # Skip initial warm-up iterations
                        print(f"Iteration {iteration + 1}: Success Rate {result['success_rate']:.2f}%")
                        continue
                    for key in metrics:
                        metrics[key].append(result[key])
                    print(f"Iteration {iteration + 1}: Success Rate {result['success_rate']:.2f}%")
                except Exception as e:
                    print(f"Test iteration failed: {e}")

            server_manager.stop_containers(n)
            time.sleep(10)

            # Write averaged results
            avg_results = {k: statistics.mean(v) for k, v in metrics.items()}
            avg_results["Threshold"] = t
            writer.writerow({
                "N": n,
                "Threshold": t,
                "Avg Response Time (s)": avg_results["avg_response_time"],
                "Throughput (req/s)": avg_results["throughput"],
                "Error Rate (%)": avg_results["error_rate"],
                "Total Time (s)": avg_results["total_time"],
                "Success Rate (%)": avg_results["success_rate"],
                "mode": mode
            })

    print("\nTesting complete")


def load_data(filename):
    data = pd.read_csv(f'{filename}')
    return data["Avg Response Time (s)"].values, data["Throughput (req/s)"].values, data["Error Rate (%)"].values, data["Total Time (s)"].values


def plot_results():
    centralised_df = pd.read_csv("c-vs-d-test-results/test_results_centralized.csv")
    decentralised_df = pd.read_csv("c-vs-d-test-results/test_results_decentralized.csv")

    # Extract unique labels based on (N, Threshold)
    labels = sorted(
        {f"N={row['N']},T={row['Threshold']}" for _, row in decentralised_df.iterrows()}
        | {"N=1,T=1"}  # Explicitly adding N=1, T=1
    )

    # Process centralized data (only one row)
    centralised = [round(centralised_df["Avg Response Time (s)"].values[0], 4), 0, 0]

    # Extract one_round and two_round response times
    one_round = []
    two_round = []

    for label in labels:
        n, t = map(int, [label.split("=")[1].split(",")[0], label.split("=")[2]])
        one = decentralised_df[
            (decentralised_df["N"] == n) & (decentralised_df["Threshold"] == t) & (
                        decentralised_df["mode"] == "one_round")
            ]["Avg Response Time (s)"]

        two = decentralised_df[
            (decentralised_df["N"] == n) & (decentralised_df["Threshold"] == t) & (
                        decentralised_df["mode"] == "two_round")
            ]["Avg Response Time (s)"]

        one_round.append(round(one.mean(), 4) if not one.empty else 0)
        two_round.append(round(two.mean(), 4) if not two.empty else 0)

    # Print the results
    print("labels =", labels)
    print("centralised =", centralised)
    print("one_round =", one_round)
    print("two_round =", two_round)

    x = np.arange(len(labels))

    # Plot
    fig, ax = plt.subplots(figsize=(8, 6))

    ax.bar(x, centralised, label='Centralised', color='orange')
    ax.bar(x, two_round, label='Two Round', color='lightskyblue')
    ax.bar(x, one_round, label='One Round', color='royalblue')

    # Labels and Title
    ax.set_ylabel("Avg Response Time (s)")
    ax.set_title("Average Response Time Comparison")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    # Show plot
    plt.savefig('c-vs-d-test-results/c_vs_d_plot.png')
    plt.show()


if __name__ == "__main__":
    # Configuration parameters
    KEYS_DIR = os.path.abspath("../signing_nodes/keys")
    DOCKER_IMAGE = "frost-node"
    modes=["two_round", "one_round"]
    Nginx_config_path= os.path.abspath("../signing_nodes/nginx/nginx.conf")
    CONTAINER_NAME = "frost-container"
    NETWORK_NAME = "signing_nodes_my-network"
    CLEANUP_SCRIPT = os.path.abspath("../signing_nodes/clean_up.sh")
    TEST_URL = "http://127.0.0.1:3030/sign"
    TEST_PAYLOAD = {"hash": "test_message"}
    REQUESTS_PER_TEST = 100
    THRESHOLDS = [2]
    NODES = 10
    settings = [(1,1),(3,2),(5,3)]

    for setting in settings:
        n = setting[0]
        t = setting[1]
        for mode in modes:
            if n == 1 and t == 1 :
                if mode == "one_round": continue
                Nginx_config_path=os.path.abspath("../signing_nodes/nginx/nginx.conf_1n")
            run_batch_tests_with_repeatition(
                keys_dir=KEYS_DIR,
                docker_image_name=DOCKER_IMAGE,
                container_name=CONTAINER_NAME,
                network_name=NETWORK_NAME,
                cleanup_script=CLEANUP_SCRIPT,
                nginx_config_path=Nginx_config_path,
                url=TEST_URL,
                payload=TEST_PAYLOAD,
                num_requests=REQUESTS_PER_TEST,
                thresholds=[t],
                n=n,
                mode=mode,
                num_commitments=50000,
            )
    plot_results()
