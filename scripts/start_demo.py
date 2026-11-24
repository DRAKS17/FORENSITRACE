"""
ForensiTrace - One-Command Startup & Demo Orchestrator (PURVA, DAKSH)
Prepares the database, seeds demo evidence, runs correlation with ML anomaly scoring,
starts backend and frontend servers, and opens the dashboard.
"""

from scripts.run_demo import main

if __name__ == "__main__":
    main()
