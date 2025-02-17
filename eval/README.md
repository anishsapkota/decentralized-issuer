# Running Tests  

## Prerequisites  
Before running the tests, ensure that:  
- Your Kafka broker is set up and running in a Docker container.  
- You have already built the Docker image for the signing nodes.  

## Steps to Run Tests  

### 1. Create and activate a virtual environment  
```bash
python -m venv .venv
source .venv/bin/activate

   ```
2. install python dependencies
 ```bash
  pip install -r requirement.txt   
 ```
3. run tests `python3 <name-of-test.py>`

