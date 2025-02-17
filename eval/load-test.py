import ast
import os
import time
import csv

import pandas as pd
import requests
import concurrent.futures
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List
from container_manager import ContainerManager

class ThroughputTester:
    def __init__(self, base_url: str, endpoint: str, payload: Dict, container_manager: ContainerManager, mode:str):
        self.base_url = base_url
        self.endpoint = endpoint
        self.payload = payload
        self.results = []
        self.latencies = []
        self.container_manager = container_manager
        self.mode = mode

    def _send_request(self):
        start_time = time.perf_counter()
        try:
            response = requests.post(
                f"{self.base_url}/{self.endpoint}",
                json=self.payload,
                timeout=5
            )
            latency = time.perf_counter() - start_time

            if response.status_code == 200:
                return True, latency
            return False, latency
        except Exception as e:
            return False, time.perf_counter() - start_time

    def _run_phase(self, concurrency: int, duration: int):
        total_requests = 0
        successful_requests = 0
        errors: Dict[str, int] = {}
        phase_latencies = []

        end_time = time.time() + duration
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []
            while time.time() < end_time:
                futures.append(executor.submit(self._send_request))
                total_requests += 1

                # Maintain constant concurrency level
                while len(futures) >= concurrency:
                    done, _ = concurrent.futures.wait(
                        futures,
                        timeout=0.1,
                        return_when=concurrent.futures.FIRST_COMPLETED
                    )

                    for future in done:
                        success, latency = future.result()
                        phase_latencies.append(latency)
                        if success:
                            successful_requests += 1
                        else:
                            error_type = "Unknown"
                            if future.exception():
                                error_type = type(future.exception()).__name__
                            errors[error_type] = errors.get(error_type, 0) + 1

                    futures = [f for f in futures if not f.done()]

        return {
            "concurrency": concurrency,
            "duration": duration,
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "error_distribution": errors,
            "throughput": successful_requests / duration,
            "avg_latency": np.mean(phase_latencies) if phase_latencies else 0,
            "p95_latency": np.percentile(phase_latencies, 95) if phase_latencies else 0,
            "p99_latency": np.percentile(phase_latencies, 99) if phase_latencies else 0,
        }

    def run_test(self, phases: List[Dict]):
        """Run throughput test with different concurrency levels

        Args:
            phases: List of dictionaries specifying test phases
            Example:
            [
                {"concurrency": 10, "duration": 30},  # Warm-up phase
                {"concurrency": 50, "duration": 60},  # Main test
                {"concurrency": 100, "duration": 60},  # Stress test
            ]
        """
        print(self.mode)
        print("Starting throughput test...")
        for phase in phases:
            print(f"\nRunning phase: {phase['concurrency']} concurrent users for {phase['duration']}s")
            result = self._run_phase(phase["concurrency"], phase["duration"])
            self.results.append(result)
            self._print_phase_summary(result)

        self._save_results()

    def _print_phase_summary(self, result: Dict):
        print(f"\nPhase Summary ({result['concurrency']} concurrent users):")
        print(f"  Throughput: {result['throughput']:.2f} req/s")
        print(f"  Success Rate: {(result['successful_requests'] / result['total_requests']) * 100:.2f}%")
        print(f"  Average Latency: {result['avg_latency'] * 1000:.2f}ms")
        print(f"  P95 Latency: {result['p95_latency'] * 1000:.2f}ms")
        print(f"  P99 Latency: {result['p99_latency'] * 1000:.2f}ms")
        print("  Errors:")
        for error, count in result["error_distribution"].items():
            print(f"    {error}: {count}")

    def _save_results(self):
        filename = f"load-test-results/load_test_{self.mode}.csv"
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Concurrency", "Duration", "Total Requests",
                "Successful Requests", "Throughput (req/s)",
                "Avg Latency (ms)", "P95 Latency (ms)", "P99 Latency (ms)",
                "Errors"
            ])

            for result in self.results:
                writer.writerow([
                    result["concurrency"],
                    result["duration"],
                    result["total_requests"],
                    result["successful_requests"],
                    result["throughput"],
                    result["avg_latency"] * 1000,
                    result["p95_latency"] * 1000,
                    result["p99_latency"] * 1000,
                    str(result["error_distribution"])
                ])
        print(f"\nResults saved to {filename}")

def load_data(filename):
    data = pd.read_csv(f'load-test-results/{filename}')
    return data["Errors"].values, data["Total Requests"].values, data["Concurrency"].values, data["Throughput (req/s)"].values, data["Avg Latency (ms)"].values, data["P95 Latency (ms)"].values, data["P99 Latency (ms)"].values


def plot_results(title: str):
    # Load data from files
    errors_one_round, num_req_one_round, concurrency_one_round, throughput_one_round, avg_latency_one_round, p95_latency_one_round, p99_latency_one_round = load_data(
        "load_test_one_round.csv")
    errors_two_round, num_req_two_round, concurrency_two_round, throughput_two_round, avg_latency_two_round, p95_latency_two_round, p99_latency_two_round = load_data(
        "load_test_two_round.csv")

    # Create plots
    plt.figure(figsize=(12, 10))

    # Throughput Plot
    plt.subplot(3, 2, 1)
    plt.plot(concurrency_two_round, throughput_two_round, marker='o', linestyle='-', label="Two Rounds")
    plt.plot(concurrency_one_round, throughput_one_round, marker='s', linestyle='--', label="One Round")
    plt.xlabel("Concurrency")
    plt.ylabel("Throughput (req/s)")
    plt.title("Throughput vs. Concurrency")
    plt.legend()
    plt.grid(True)

    # Average Latency Plot
    plt.subplot(3, 2, 2)
    plt.plot(concurrency_two_round, avg_latency_two_round, marker='o', linestyle='-', label="Two Rounds")
    plt.plot(concurrency_one_round, avg_latency_one_round, marker='s', linestyle='--', label="One Round")
    plt.xlabel("Concurrency")
    plt.ylabel("Avg Latency (ms)")
    plt.title("Average Latency vs. Concurrency")
    plt.legend()
    plt.grid(True)

    # P95 Latency Plot
    plt.subplot(3, 2, 3)
    plt.plot(concurrency_two_round, p95_latency_two_round, marker='o', linestyle='-', label="Two Rounds")
    plt.plot(concurrency_one_round, p95_latency_one_round, marker='s', linestyle='--', label="One Round")
    plt.xlabel("Concurrency")
    plt.ylabel("P95 Latency (ms)")
    plt.title("P95 Latency vs. Concurrency")
    plt.legend()
    plt.grid(True)

    # P99 Latency Plot
    plt.subplot(3, 2, 4)
    plt.plot(concurrency_two_round, p99_latency_two_round, marker='o', linestyle='-', label="Two Rounds")
    plt.plot(concurrency_one_round, p99_latency_one_round, marker='s', linestyle='--', label="One Round")
    plt.xlabel("Concurrency")
    plt.ylabel("P99 Latency (ms)")
    plt.title("P99 Latency vs. Concurrency")
    plt.legend()
    plt.grid(True)

    # Error Rate Plot - Moving it to a separate 5th plot
    plt.subplot(3, 1, 3)

    def extract_errors(error_list):
        parsed_errors = [ast.literal_eval(e) if e != '{}' else {} for e in error_list]
        return [e.get("Unknown", 0) for e in parsed_errors]

    # Extract error counts
    errors_one_round_values = extract_errors(errors_one_round)
    errors_two_round_values = extract_errors(errors_two_round)

    plt.plot(concurrency_two_round, errors_two_round_values, marker='o', linestyle='-', label="Two Rounds")
    plt.plot(concurrency_one_round, errors_one_round_values, marker='s', linestyle='--', label="One Round")
    plt.xlabel("Concurrency")
    plt.ylabel("Error Count")
    plt.title("Error Distribution vs Concurrency")
    plt.legend()
    plt.grid(True)

    # Adjust layout and show the plot
    #plt.tight_layout(rect=[0, 0, 1, 0.97])  # Prevent title overlap
    plt.tight_layout()
    #plt.suptitle(title, fontsize=16, fontweight='bold')
    plt.savefig('load-test-results/1r_vs_2r_10n7t.png')
    plt.show()

if __name__ == "__main__":
    SERVER_URL = "http://localhost:3030"
    ENDPOINT = "sign"
    PAYLOAD = {"hash": "test_message"}
    MODES = ["one_round","two_round"]
    TEST_PHASES = [
        {"concurrency": 10, "duration": 30},
        {"concurrency": 50, "duration": 60},
        {"concurrency": 100, "duration": 60},
        {"concurrency": 200, "duration": 60},
        {"concurrency": 300, "duration": 60},
        {"concurrency": 400, "duration": 60},
        {"concurrency": 500, "duration": 60},
    ]

    for mode in MODES:
        container_manager = ContainerManager(
            keys_dir=os.path.abspath("../signing_nodes/keys"),
            docker_image_name="frost-node",
            network_name="signing_nodes_my-network",
            cleanup_script=os.path.abspath("../signing_nodes/clean_up.sh"),
            nginx_config_path=os.path.abspath("../signing_nodes/nginx/nginx.conf"),
            mode=mode,
            num_commitments=100000
        )

        tester = ThroughputTester(
            base_url=SERVER_URL,
            endpoint=ENDPOINT,
            payload=PAYLOAD,
            container_manager=container_manager,
            mode=mode
        )

        try:
            # Start servers before running the test
            container_manager.start_containers(total_nodes=10, threshold=7)
            time.sleep(60)
            tester.run_test(TEST_PHASES)
        finally:
            # Stop servers after testing
            container_manager.stop_containers(total_nodes=10)


    plot_results(title="10n 7t : one_round vs two_round")