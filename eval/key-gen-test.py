import time
import os
import csv
import matplotlib.pyplot as plt
import pandas as pd
from typing import List
from container_manager import ContainerManager as ServerManager

def check_keys_and_restart(server_manager: ServerManager, n: int, t: int, max_retries: int = 3) -> (bool, float):
    for attempt in range(max_retries):
        try:
            # First cleanup before starting fresh
            server_manager.stop_containers(n)
            time.sleep(10)

            if not server_manager.start_containers(n, t):
                continue

            time.sleep(5)

            start_time = time.time()
            max_wait = 60  # 1 minutes timeout
            poll_interval = 1  # check every 1 seconds

            while time.time() - start_time < max_wait:
                key_files = [f for f in os.listdir(server_manager.keys_dir)
                             if f.endswith(".txt")]
                if len(key_files) == n:
                    key_gen_time = time.time() - start_time
                    print(f"Keys generated in {key_gen_time:.2f}s")
                    return True, key_gen_time
                time.sleep(poll_interval)

            print(f"Key check timeout (attempt {attempt + 1}/{max_retries})")

        except Exception as e:
            print(f"Key check error: {str(e)}")

        server_manager.stop_containers(n)
        time.sleep(10)

    return False, 0.0


def run_key_gen_test(
        keys_dir: str,
        docker_image_name: str,
        network_name: str,
        cleanup_script: str,
        nginx_config_path:str,
        node_threshold_pairs: List[tuple],
):
    with open("key-gen-test-results/test_results_key_gen.csv", "w", newline="") as csvfile:
        fieldnames = [
            "Nodes", "Threshold", "KeyGenTime"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for n, t in node_threshold_pairs:
            if t > n:
                print(f"Skipping invalid combination N={n}, T={t}")
                continue

            server_manager = ServerManager(
                keys_dir, docker_image_name,
                 network_name, cleanup_script,nginx_config_path,"two_round",1000
            )

            print(f"\n=== KeyGen N={n}, T={t} ===")

            # Measure key generation time
            key_success, key_gen_time = check_keys_and_restart(server_manager, n, t)
            if not key_success:
                print(f"Skipping N={n}, T={t} due to key generation failure")
                continue

            time.sleep(10)

            writer.writerow({
                "Nodes": n,
                "Threshold": t,
                "KeyGenTime": key_gen_time,
            })

            server_manager.stop_containers(n)
            time.sleep(10)


def plot_keygen():
    data = pd.read_csv('key-gen-test-results/test_results_key_gen.csv')

    plt.figure(figsize=(6, 4))  # Adjust figure size

    # Key Generation Time Plot
    for n in data['Nodes'].unique():
        subset = data[data['Nodes'] == n]
        plt.plot(subset['Threshold'], subset['KeyGenTime'], marker='o', label=f'N={n}')

    plt.xlabel('Threshold')
    plt.ylabel('Key Generation Time (s)')
    plt.title('Key Generation Time vs Threshold')
    plt.legend()
    plt.grid(True)
    plt.savefig("key-gen-test-results/key_gen.png")
    plt.show()

if __name__ == "__main__":
    #Configuration
    CONFIG = {
        "keys_dir": os.path.abspath('../signing_nodes/keys'),
        "docker_image": "frost-node",
        "network_name": "signing_nodes_my-network",
        "cleanup_script": os.path.abspath("../signing_nodes/clean_up.sh"),
        "nginx_config_path": os.path.abspath("../signing_nodes/nginx/nginx.conf"),
        "test_url": "http://localhost:3030/sign",
        "node_threshold_pairs": [
            (3,2),(3,3),
            (5, 3), (5, 4), (5, 5),
            (10, 6), (10, 7), (10, 8), (10, 9), (10, 10),
            (15, 8), (15, 9), (15, 10), (15, 11), (15, 12), (15, 13)
        ]
    }

    run_key_gen_test(
        keys_dir=CONFIG["keys_dir"],
        docker_image_name=CONFIG["docker_image"],
        network_name=CONFIG["network_name"],
        cleanup_script=CONFIG["cleanup_script"],
        nginx_config_path=CONFIG["nginx_config_path"],
        node_threshold_pairs=CONFIG["node_threshold_pairs"]
    )

    plot_keygen()