import sys
import os

# Add the project root and src to the path so we can import src modules
project_root = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "src"))

from src.ui.app import create_app

def main():
    print("========================================")
    print("Neuro-Symbolic Fuzzer UI Initialization")
    print("========================================")
    print("Starting interactive viewer...")
    print("Please open your web browser to http://127.0.0.1:8050")
    print("You can upload your binary directly from the web portal.\n")
    
    app = create_app()
    app.run(debug=True, port=8050)

if __name__ == "__main__":
    main()
