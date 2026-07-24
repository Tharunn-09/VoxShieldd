# Real-time Audio Forensics Module for Voice Security

**Problem**: Generative AI voice cloning bypasses voice biometrics using just seconds of audio. Metadata defenses are spoofable.

**Solution**: Analyzes live call spectrograms for synthetic artifacts (pitch/frequency micro-imperfections) and flags "High Risk" within first 10 seconds.

## Tech Stack
- Python, Librosa (spectrograms/MFCC), SciPy, Scikit-learn (RandomForest detector)
- SoundFile for I/O
- (Optional) PyAudio / sounddevice for live mic, WebRTC VAD, PyTorch/ResNet for advanced version

## Features
- Real-time chunked processing (1-second windows)
- Forensic feature extraction targeting GAN/TTS artifacts:
  - High-frequency energy ratio
  - Spectral flatness & centroid variance
  - MFCC statistics + deltas
  - Spectral flux (consistency anomalies)
- Streaming risk scoring with final verdict at ~10s
- Simple energy-based VAD
- Prototype ML model (RandomForest) trained on synthetic distinguishing features
- Works on audio files (simulates live) or can be extended to mic streams

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
# For live mic (optional, may need system libs):
# pip install pyaudio sounddevice
```

### 2. Run the demo
```bash
python audio_forensics.py
```

This will:
- Create a synthetic test tone (`sample_call.wav`) if none exists
- Process the first 10 seconds in 1s chunks
- Output per-chunk risk scores and a final verdict

### 3. Analyze your own audio file
Edit the script or use in Python:

```python
from audio_forensics import AudioForensicsModule

module = AudioForensicsModule()
result = module.analyze_audio_file("your_call_recording.wav")
print(result['verdict'])
print(result['recommendation'])
```

### Expected Output Example
```
[INFO] Analyzing audio file: sample_call.wav
  [0.0s] Risk: 0.320 | Collecting data...
  [1.0s] Risk: 0.285 | Low risk so far
  ...
=== FINAL VERDICT ===
Risk Score: 0.31
Verdict: LOW RISK: Natural voice characteristics
Recommendation: Proceed normally
```

## How It Detects Synthetic Voices
Modern voice clones (TTS, voice conversion, GANs) often leave traces:
- Overly consistent pitch / reduced micro-variations
- Unnatural high-frequency boost or smoothing
- Lower spectral flatness (too "clean")
- Phase/timbre inconsistencies detectable in MFCCs and flux

The model learns combinations of these.

## Extending to Live Calls (Production Path)
Replace file processing with a microphone stream:

```python
import pyaudio
# ... (see commented code or implement stream generator)
def mic_generator():
    # Use PyAudio to yield 1-second chunks at 16kHz
    ...

for result in module.process_live_stream(mic_generator()):
    if 'final' in result:
        # Trigger alert / UI flag
        break
```

For better VAD, integrate `webrtcvad`.

## Model Notes
- Prototype uses a lightweight RandomForest (saved as `.pkl`)
- For production: Train on large datasets like ASVspoof 2019/2021 or WaveFake using CNN (ResNet) or Transformer on full spectrograms.
- Export to ONNX for low-latency inference if needed.
- Retrain periodically as cloning tech evolves.

## Limitations (Prototype)
- Dummy model (not trained on real spoofed data)
- Simple VAD (energy-based)
- No phase or advanced deep learning features yet
- Assumes mono 16kHz audio

## Next Steps / Improvements
1. Collect/buy labeled dataset and retrain model
2. Add PyTorch CNN or Transformer encoder (as mentioned in your tech stack)
3. Integrate real-time microphone + WebRTC VAD
4. Add ONNX export + runtime
5. Spectrogram visualization (matplotlib) for debugging
6. Multi-language / accent robustness testing

## College Project Tips
- This directly addresses the "Expected Outcome"
- Demo with both "real" (recorded) and "synthetic" (generated via free TTS tools like Tortoise or Coqui) audio for contrast
- Add a simple Streamlit/Gradio UI for visual risk gauge
- Measure latency: should be <200ms per chunk on CPU

Project by Lovely Professional University student.

For questions or enhancements, provide more details!
