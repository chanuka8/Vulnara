import sys
from pathlib import Path
from dotenv import load_dotenv

# 1. Load environment variables from the .env file
load_dotenv()

# 2. Add the 'src' directory to the Python path so modules resolve correctly
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# 3. Import and run the CLI app
from vulnara.app import app

if __name__ == "__main__":
    app()