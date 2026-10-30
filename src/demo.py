"""
Command-Line Demonstration Interface for SCAMLENS AI
Demonstrates offline inference using the trained Random Forest model and FeatureExtractor.
Analyzes 4 benchmark demonstration messages and supports interactive user testing.
"""

import sys
from typing import List
from src.models.predictor import get_predictor, ScamLensPredictor

DEMO_MESSAGES = [
    {
        "name": "Example A — Normal Message",
        "text": "Hi, I will reach college at 10 AM tomorrow. Please wait for me."
    },
    {
        "name": "Example B — Suspicious Security Message",
        "text": "URGENT! Your bank account will be blocked. Verify your account immediately."
    },
    {
        "name": "Example C — Reward Scam Message",
        "text": "Congratulations! You have won a free cash prize. Claim your reward now!"
    },
    {
        "name": "Example D — URL Phishing Message",
        "text": "Your account needs verification. Click http://example.com now to continue."
    }
]


def display_result(result: dict, title: str = "SCAMLENS AI RESULT"):
    """Format and print prediction result box."""
    print("=" * 65)
    print(f"  {title}")
    print("=" * 65)

    if not result.get("valid", True):
        print(f"Error: {result.get('error')}")
        print("=" * 65 + "\n")
        return

    pred = result["prediction"]
    score = result["risk_score"]
    level = result["risk_level"]
    p_scam = result["phishing_probability"] * 100.0
    p_legit = result["legitimate_probability"] * 100.0

    print(f"Message Preview : \"{result['message_preview']}\"")
    print("-" * 65)
    print(f"Prediction      : {pred}")
    print(f"Risk Score      : {score:.2f} / 100")
    print(f"Risk Level      : {level}")
    print(f"Phishing Prob.  : {p_scam:.2f}%")
    print(f"Legitimate Prob.: {p_legit:.2f}%")
    if result.get("scan_id"):
        print(f"Logged Scan ID  : #{result['scan_id']}")

    print("\nExplanatory Indicators:")
    for ind in result.get("indicators", []):
        print(f"  • {ind}")
    print("=" * 65 + "\n")


def run_benchmark_demo(predictor: ScamLensPredictor):
    """Run automated analysis on the 4 benchmark test messages."""
    print("\n" + "#" * 65)
    print("      SCAMLENS AI — BENCHMARK DEMONSTRATION MESSAGES")
    print("#" * 65 + "\n")

    for demo in DEMO_MESSAGES:
        res = predictor.predict(demo["text"])
        display_result(res, title=f"DEMO: {demo['name']}")


def interactive_cli(predictor: ScamLensPredictor):
    """Interactive loop for entering custom messages."""
    print("\n" + "=" * 65)
    print("        SCAMLENS AI — INTERACTIVE CLI DETECTOR")
    print(" Type your message and press ENTER. Type 'exit' or 'q' to quit.")
    print("=" * 65 + "\n")

    while True:
        try:
            user_input = input("Enter message > ").strip()
            if not user_input:
                continue
            if user_input.lower() in ["exit", "quit", "q"]:
                print("Exiting SCAMLENS AI Demo. Goodbye!")
                break

            res = predictor.predict(user_input)
            display_result(res, title="INTERACTIVE ANALYSIS RESULT")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting SCAMLENS AI Demo. Goodbye!")
            break


def main():
    """Main demo entry point."""
    print("Initializing SCAMLENS AI Predictor...")
    predictor = get_predictor()

    # Always run benchmark demo first
    run_benchmark_demo(predictor)

    # Check if non-interactive (automated test run) or interactive terminal
    if sys.stdin.isatty():
        interactive_cli(predictor)


if __name__ == "__main__":
    main()
