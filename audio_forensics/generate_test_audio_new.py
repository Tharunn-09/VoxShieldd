import os
import numpy as np
import soundfile as sf

script_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(script_dir, "test_samples")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def generate_synthetic_signals():
    files = {
        'synthetic_pure_sine': os.path.join(OUTPUT_DIR, 'synthetic_pure_sine.wav'),
        'real_noisy_voice': os.path.join(OUTPUT_DIR, 'real_noisy_voice.wav'),
        'voice_harmonics': os.path.join(OUTPUT_DIR, 'voice_harmonics.wav'),
        'am_modulated_speech': os.path.join(OUTPUT_DIR, 'am_modulated_speech.wav'),
        'sparse_vad_test': os.path.join(OUTPUT_DIR, 'sparse_vad_test.wav')
    }
    
    sr = 16000
    duration = 12.0
    t = np.linspace(0, duration, int(sr * duration))
    
    if not os.path.exists(files['synthetic_pure_sine']):
        y = 0.5 * np.sin(2 * np.pi * 200 * t)
        sf.write(files['synthetic_pure_sine'], y, sr)
        
    if not os.path.exists(files['real_noisy_voice']):
        y = 0.4 * np.sin(2 * np.pi * 220 * t) + 0.3 * np.random.randn(len(t))
        sf.write(files['real_noisy_voice'], y, sr)
        
    if not os.path.exists(files['voice_harmonics']):
        f0 = 150.0
        y = (0.5 * np.sin(2 * np.pi * f0 * t) +
             0.25 * np.sin(2 * np.pi * f0 * 2 * t) +
             0.12 * np.sin(2 * np.pi * f0 * 3 * t) +
             0.05 * np.random.randn(len(t)))
        sf.write(files['voice_harmonics'], y, sr)
        
    if not os.path.exists(files['am_modulated_speech']):
        y = np.sin(2 * np.pi * 300 * t) * (1.0 + 0.5 * np.sin(2 * np.pi * 4 * t))
        sf.write(files['am_modulated_speech'], y, sr)
        
    if not os.path.exists(files['sparse_vad_test']):
        y = np.zeros(len(t))
        for start_s in [1, 4, 7, 10]:
            start_idx = int(start_s * sr)
            end_idx = int((start_s + 0.8) * sr)
            y[start_idx:end_idx] = 0.4 * np.sin(2 * np.pi * 200 * t[start_idx:end_idx])
        sf.write(files['sparse_vad_test'], y, sr)
        
    return files

def generate_gtts_voice():
    path = os.path.join(OUTPUT_DIR, "gtts_voice.wav")
    if os.path.exists(path):
        return path
    
    try:
        from gtts import gTTS
        tts = gTTS(text="Welcome to UCO Bank VoxShield Voice Forensics. This is a natural human voice sample for testing.", lang='en')
        mp3_path = os.path.join(OUTPUT_DIR, "gtts_voice.mp3")
        tts.save(mp3_path)
        import librosa
        y, sr = librosa.load(mp3_path, sr=16000)
        sf.write(path, y, 16000)
        os.remove(mp3_path)
    except Exception:
        sr = 16000
        t = np.linspace(0, 12.0, sr * 12)
        f0 = 120.0
        y = (0.4 * np.sin(2 * np.pi * f0 * t) +
             0.2 * np.sin(2 * np.pi * f0 * 2 * t) +
             0.1 * np.sin(2 * np.pi * f0 * 3 * t))
        env = 0.5 * (1.0 + np.sin(2 * np.pi * 1.5 * t) * np.cos(2 * np.pi * 0.3 * t))
        y = y * env + 0.05 * np.random.randn(len(t))
        sf.write(path, y, sr)
    return path

def generate_pyttsx3_voice():
    path = os.path.join(OUTPUT_DIR, "pyttsx3_voice.wav")
    if os.path.exists(path):
        return path
        
    try:
        import pyttsx3
        engine = pyttsx3.init()
        temp_path = os.path.join(OUTPUT_DIR, "pyttsx3_temp.wav")
        engine.save_to_file("VoxShield synthetic voice alert. High risk of speech synthesis detected.", temp_path)
        engine.runAndWait()
        import librosa
        y, sr = librosa.load(temp_path, sr=16000)
        sf.write(path, y, 16000)
        os.remove(temp_path)
    except Exception:
        sr = 16000
        t = np.linspace(0, 12.0, sr * 12)
        f0 = 200.0
        y = 0.6 * np.sin(2 * np.pi * f0 * t)
        y += 0.002 * np.random.randn(len(t))
        sf.write(path, y, sr)
    return path
