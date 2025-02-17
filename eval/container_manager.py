import subprocess

class ContainerManager:
    def __init__(self, keys_dir: str, docker_image_name: str, network_name: str, cleanup_script: str, nginx_config_path: str, mode: str, num_commitments:int):
        self.keys_dir = keys_dir
        self.docker_image_name = docker_image_name
        self.network_name = network_name
        self.cleanup_script = cleanup_script
        self.nginx_config_path = nginx_config_path
        self.nginx_container_name = "nginx-load-balancer"
        self.num_commitments = num_commitments
        self.mode = mode

    def start_nginx(self) -> bool:
        print("Starting NGINX load balancer...")
        try:
            result = subprocess.run(["docker", "ps", "--filter", f"name={self.nginx_container_name}", "--quiet"], capture_output=True, text=True)
            if result.stdout.strip():
                print("NGINX container is already running.")
                return False

            command = [
                "docker", "run", "--rm", "-d",
                "-p", "3030:80",
                "-v", f"{self.nginx_config_path}:/etc/nginx/nginx.conf",
                "--network", self.network_name,
                "--name", self.nginx_container_name,
                "nginx"
            ]
            subprocess.run(command, check=True)
            print("NGINX load balancer started successfully.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to start NGINX: {e}")
            return False

    def stop_nginx(self):
        print("Stopping NGINX load balancer...")
        try:
            subprocess.run(["docker", "stop", self.nginx_container_name], check=True)
            print("NGINX load balancer stopped successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error stopping NGINX: {e}")

    def start_redis(self) -> bool:
        print("Starting Redis...")
        try:
            result = subprocess.run(["docker", "ps", "--filter", f"name=redis", "--quiet"], capture_output=True, text=True)
            if result.stdout.strip():
                print("Redis container is already running.")
                return False

            command = ["docker", "run", "--rm", "-d", "-p", "6379:6379", "--network", self.network_name, "--name", "redis", "redis"]
            subprocess.run(command, check=True)
            print("Redis started successfully.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to start Redis: {e}")
            return False

    def stop_redis(self):
        print("Stopping Redis...")
        try:
            subprocess.run(["docker", "stop", "redis"], check=True)
            print("Redis stopped successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error stopping Redis: {e}")

    def start_containers(self, total_nodes: int, threshold: int) -> bool:
        print(f"Starting {total_nodes} servers with N={total_nodes} and T={threshold}...")
        try:
            self.start_redis()

            for node_id in range(1, total_nodes + 1):
                container_name = f"frost-node-{node_id}"
                result = subprocess.run(["docker", "ps", "--filter", f"name={container_name}", "--quiet"], capture_output=True, text=True)
                if result.stdout.strip():
                    print(f"Container {container_name} is already running.")
                    continue

                command = [
                    "docker", "run", "--rm", "-d",
                    "-v", f"{self.keys_dir}:/app/keys",
                    "-e", f"NODE_ID={node_id}",
                    "-e", f"N={total_nodes}",
                    "-e", f"T={threshold}",
                    "-e", f"NUM_COMMITMENTS={self.num_commitments}",
                    "-e", f"MODE={self.mode}",
                    "--network", self.network_name,
                    "--name", container_name,
                    self.docker_image_name
                ]
                subprocess.run(command, check=True)
                print(f"Started container {container_name}.")

            self.start_nginx()

            print(f"Successfully started {total_nodes} servers, Redis, and NGINX load balancer.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to start servers: {e}")
            return False

    def stop_containers(self, total_nodes: int):
        print("Stopping servers and NGINX load balancer...")
        try:
            for node_id in range(1, total_nodes + 1):
                container_name = f"frost-node-{node_id}"
                subprocess.run(["docker", "stop", container_name], check=True)
                print(f"Stopped container {container_name}.")

            self.stop_nginx()
            self.stop_redis()
        except subprocess.CalledProcessError as e:
            print(f"Error stopping containers: {e}")
        finally:
            self.run_cleanup()

    def run_cleanup(self):
        print("Running cleanup script...")
        try:
            subprocess.run([self.cleanup_script], check=True)
            print("Cleanup completed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error during cleanup: {e}")
