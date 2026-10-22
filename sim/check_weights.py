"""Inspect experimental adaptive weights; no network rules are changed."""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from core.model import adaptive_weights


def main():
    print("ADAPTIVE WEIGHTS ONLY; the live controller still uses fixed weights.")
    print("Design parameters: threshold=0.20, steepness=15, delay_share=0.70")
    print("Battery   alpha(delay)   beta(energy)   gamma(carbon)   sum")
    for energy in (0.90, 0.75, 0.40, 0.30, 0.20, 0.10):
        weights = adaptive_weights(energy)
        alpha, beta, gamma = weights
        print("%5.0f%%       %.3f          %.3f           %.3f       %.3f" %
              (100 * energy, alpha, beta, gamma, sum(weights)))
    print("Beta rises as battery falls. No standby rule is implemented here.")
    print("Changing all weights does not guarantee that total cost rises.")
    print("This is not yet a fixed-versus-adaptive routing experiment.")


if __name__ == "__main__":
    main()
