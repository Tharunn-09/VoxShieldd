"""
run_tests.py
-------------------------------------------------------------
Runs all generated test audio files through AudioForensicsModule
Compatible with Python 3.13 | No Coqui TTS needed

Run: python run_tests.py
"""

import os
import sys
import io
import numpy as np

# Ensure UTF-8 output encoding for emojis and box drawing characters on Windows console
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Ensure script directory is in the import search path
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

from audio_forensics import AudioForensicsModule        # Your existing file
from generate_test_audio_new import (                    # Updated generator
    generate_gtts_voice,
    generate_pyttsx3_voice,
    generate_synthetic_signals,
    OUTPUT_DIR
)
# ✅ generate_coqui_voice REMOVED - not compatible with Python 3.12+


def run_all_tests():

    print("=" * 65)
    print("  AUDIO FORENSICS - COMPLETE TEST SUITE")
    print("=" * 65)

    # Initialize forensics module
    forensics = AudioForensicsModule(
        sample_rate     = 16000,
        chunk_duration  = 1.0,
        decision_window = 10.0
    )

    results = []

    # -- Helper: test one file ----------------------------
    def test_file(label, path, expected):
        """Run one audio file through the forensics module."""
        if path and os.path.exists(path):
            print(f"\n{'-'*55}")
            print(f"  > Testing  : {label}")
            print(f"    File     : {path}")
            print(f"    Expected : {expected}")
            print(f"{'-'*55}")

            # Reset state for each new file
            forensics.reset_state()

            result = forensics.analyze_audio_file(
                path,
                simulate_realtime=True
            )

            results.append({
                'label'    : label,
                'path'     : path,
                'expected' : expected,
                'risk'     : result['final_risk'],
                'verdict'  : result['verdict'],
                'chunks'   : result.get('speech_chunks_analyzed', 0),
                'confidence': result.get('confidence', 0.0)
            })
        else:
            print(f"\n  ⚠ SKIP: {label}")
            print(f"    Reason : File not found → {path}")
            print(f"    Fix    : Run python generate_test_audio.py first")

    # ════════════════════════════════════════════════════
    # BATCH 0: Your existing sample_call.wav
    # ════════════════════════════════════════════════════
    print("\n[BATCH 0] Existing Sample File")
    print("-" * 55)
    test_file(
        label    = "sample_call.wav (original)",
        path     = "sample_call.wav",
        expected = "Baseline - Sine + Noise"
    )

    # ════════════════════════════════════════════════════
    # BATCH 1: Synthetic Signals (no dependencies)
    # ════════════════════════════════════════════════════
    print("\n\n[BATCH 1] Synthetic Signal Tests")
    print("-" * 55)

    # Generate if not already done
    syn_files    = generate_synthetic_signals()
    expectations = {
        'synthetic_pure_sine'  : 'HIGH RISK   🔴 (pure sine, no noise)',
        'real_noisy_voice'     : 'LOW RISK    🟢 (sine + heavy noise)',
        'voice_harmonics'      : 'MEDIUM RISK 🟡 (multi-harmonic)',
        'am_modulated_speech'  : 'HIGH RISK   🔴 (AM modulated)',
        'sparse_vad_test'      : 'VAD TEST    ⚪ (sparse bursts)'
    }

    for name, path in syn_files.items():
        test_file(
            label    = name,
            path     = path,
            expected = expectations.get(name, 'Unknown')
        )

    # ════════════════════════════════════════════════════
    # BATCH 2: gTTS Human Voice
    # ════════════════════════════════════════════════════
    print("\n\n[BATCH 2] gTTS Human-like Voice")
    print("-" * 55)

    gtts_path = os.path.join(OUTPUT_DIR, "gtts_voice.wav")

    # Try to generate if missing
    if not os.path.exists(gtts_path):
        print("  [INFO] gtts_voice.wav not found, generating...")
        gtts_path = generate_gtts_voice()

    test_file(
        label    = "gTTS Human Voice",
        path     = gtts_path,
        expected = "LOW RISK 🟢 (human-like natural voice)"
    )

    # ════════════════════════════════════════════════════
    # BATCH 3: pyttsx3 Robotic Voice
    # ════════════════════════════════════════════════════
    print("\n\n[BATCH 3] pyttsx3 Robotic/Synthetic Voice")
    print("-" * 55)

    pyttsx3_path = os.path.join(OUTPUT_DIR, "pyttsx3_voice.wav")

    # Try to generate if missing
    if not os.path.exists(pyttsx3_path):
        print("  [INFO] pyttsx3_voice.wav not found, generating...")
        pyttsx3_path = generate_pyttsx3_voice()

    test_file(
        label    = "pyttsx3 Robotic Voice",
        path     = pyttsx3_path,
        expected = "HIGH RISK 🔴 (robotic synthetic voice)"
    )

    # ════════════════════════════════════════════════════
    # FINAL RESULTS TABLE
    # ════════════════════════════════════════════════════
    print("\n\n" + "=" * 75)
    print("  FINAL RESULTS SUMMARY")
    print("=" * 75)
    print(f"  {'Audio Source':<28} {'Expected':<20} {'Risk':>6}  {'Icon'}  {'Chunks'}")
    print("  " + "-" * 70)

    for r in results:
        # Risk icon
        if r['risk'] > 0.65:
            icon = "🔴 HIGH"
        elif r['risk'] > 0.40:
            icon = "🟡 MED"
        else:
            icon = "🟢 LOW"

        print(
            f"  {r['label']:<28} "
            f"{r['expected'][:20]:<20} "
            f"{r['risk']:>6.3f}  "
            f"{icon:<10}  "
            f"{r['chunks']} chunks"
        )

    print("  " + "-" * 70)

    # Stats
    high_risk = sum(1 for r in results if r['risk'] > 0.65)
    med_risk  = sum(1 for r in results if 0.40 < r['risk'] <= 0.65)
    low_risk  = sum(1 for r in results if r['risk'] <= 0.40)

    print(f"\n  Results breakdown:")
    print(f"  🔴 High Risk  : {high_risk} file(s)")
    print(f"  🟡 Medium Risk: {med_risk} file(s)")
    print(f"  🟢 Low Risk   : {low_risk} file(s)")
    print(f"  📊 Total Tested: {len(results)} file(s)")

    print("\n  Threshold Reference:")
    print("  🔴 HIGH   : risk > 0.65  → Flag call, request verification")
    print("  🟡 MEDIUM : risk > 0.40  → Monitor closely")
    print("  🟢 LOW    : risk ≤ 0.40  → Proceed normally")
    print("=" * 75)

    return results


if __name__ == "__main__":
    run_all_tests()