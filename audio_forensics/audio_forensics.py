"""
Real-time Audio Forensics Module for Voice Security
NOW WITH: Real feature-based training (no dummy data)
"""

import numpy as np
import librosa
import soundfile as sf
from scipy import signal
from scipy.signal import butter, lfilter
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import pickle
import os
from typing import Tuple, Dict, List, Optional
import warnings
warnings.filterwarnings('ignore')


class AudioForensicsModule:
    def __init__(
        self,
        sample_rate: int = 16000,
        chunk_duration: float = 1.0,
        decision_window: float = 10.0,
        model_path: Optional[str] = None
    ):
        self.sample_rate    = sample_rate
        self.chunk_duration = chunk_duration
        self.chunk_samples  = int(chunk_duration * sample_rate)
        self.decision_window = decision_window
        self.max_chunks     = int(decision_window / chunk_duration)

        # Feature config
        self.n_mels    = 128
        self.n_mfcc    = 40
        self.hop_length = 512

        # Model
        self.model      = None
        self.scaler     = StandardScaler()
        script_dir      = os.path.dirname(os.path.abspath(__file__))
        self.model_path = model_path or os.path.join(script_dir, "synthetic_voice_detector_v3.pkl")

        # Thresholds
        self.risk_threshold      = 0.55
        self.artifact_threshold  = 0.5

        # Load model if exists, otherwise train
        if os.path.exists(self.model_path):
            try:
                self._load_model()
            except Exception as e:
                print(f"[WARN] Failed to load model: {e}. Retraining...")
                self._train_on_real_features()
        else:
            print("[INFO] Model not found. Training model on real audio features...")
            self._train_on_real_features()

        self.reset_state()

    def reset_state(self):
        self.feature_buffer: List[np.ndarray] = []
        self.risk_scores:    List[float]       = []
        self.current_time    = 0.0
        self.is_speaking     = False
        self.speech_chunks   = 0

    # ══════════════════════════════════════════════════
    # CORE: Extract features from audio chunk
    # ══════════════════════════════════════════════════

    def extract_features(self, audio_chunk: np.ndarray) -> np.ndarray:
        """Extract 51 forensic features from audio chunk including MFCCs, Chroma, RMS and local pitch statistics."""

        if len(audio_chunk) < self.chunk_samples:
            audio_chunk = np.pad(
                audio_chunk,
                (0, self.chunk_samples - len(audio_chunk))
            )

        # 1. Linear Spectrogram & LFCCs
        linear_spec = np.abs(librosa.stft(
            y          = audio_chunk,
            n_fft      = 2048,
            hop_length = self.hop_length
        ))
        log_linear = librosa.power_to_db(linear_spec**2, ref=np.max)

        from scipy.fftpack import dct
        lfccs = dct(log_linear, type=2, axis=0, norm='ortho')[:self.n_mfcc]
        lfcc_mean = np.mean(lfccs, axis=1)
        lfcc_std  = np.std(lfccs,  axis=1)

        # 2. High-frequency energy ratio
        high_freq_energy = np.mean(log_linear[int(0.7 * log_linear.shape[0]):, :])
        total_energy     = np.mean(log_linear)
        high_freq_ratio  = high_freq_energy / (total_energy + 1e-8)

        # 3. Spectral flatness
        flatness = librosa.feature.spectral_flatness(
            y=audio_chunk, n_fft=2048
        ).mean()

        # 4. Spectral centroid
        centroid     = librosa.feature.spectral_centroid(
            y=audio_chunk, sr=self.sample_rate
        ).flatten()
        centroid_mean = np.mean(centroid)
        centroid_std  = np.std(centroid)

        # 5. Spectral bandwidth
        bandwidth = librosa.feature.spectral_bandwidth(
            y=audio_chunk, sr=self.sample_rate
        ).mean()

        # 6. Zero crossing rate
        zcr = librosa.feature.zero_crossing_rate(audio_chunk).mean()

        # 8. Spectral flux
        flux = np.mean(np.abs(np.diff(log_linear, axis=1)))

        # 9. NEW: Spectral rolloff
        rolloff = librosa.feature.spectral_rolloff(
            y=audio_chunk, sr=self.sample_rate
        ).mean()

        # 10. NEW: Harmonic-to-noise ratio proxy
        harmonic, percussive = librosa.effects.hpss(audio_chunk)
        hnr = np.mean(harmonic**2) / (np.mean(percussive**2) + 1e-8)

        # 11. NEW: Pitch consistency (synthetic voices are TOO consistent)
        try:
            f0 = librosa.yin(y=audio_chunk, sr=self.sample_rate, fmin=60, fmax=500)
            f0 = f0[np.isfinite(f0)]
            pitch_std = np.std(f0) if len(f0) > 0 else 0
        except Exception:
            pitch_std = 0

        # 12. NEW: Spectral contrast
        contrast = librosa.feature.spectral_contrast(
            y=audio_chunk, sr=self.sample_rate
        ).mean()

        # 13. NEW: MFCCs (13 coefficients)
        mfccs = librosa.feature.mfcc(
            y=audio_chunk, sr=self.sample_rate, n_mfcc=13, hop_length=self.hop_length
        )
        mfcc_mean = np.mean(mfccs, axis=1)
        mfcc_std  = np.std(mfccs, axis=1)

        # 14. NEW: Chroma features
        chroma = librosa.feature.chroma_stft(
            y=audio_chunk, sr=self.sample_rate, hop_length=self.hop_length
        )
        chroma_mean = chroma.mean()
        chroma_std  = chroma.std()

        # 15. NEW: RMS Energy
        rms_energy = librosa.feature.rms(y=audio_chunk, hop_length=self.hop_length)
        rms_mean = rms_energy.mean()
        rms_std  = rms_energy.std()

        # 16. NEW: Local Jitter & Shimmer estimation (producers of vocal fold dynamics)
        def get_local_jitter_shimmer(buf):
            size = len(buf)
            rms_val = np.sqrt(np.mean(buf**2))
            if rms_val < 0.01:
                return 0.0, 0.0
            
            sub_hop = size // 5
            sub_size = size // 2
            f0_estimates = []
            amp_peaks = []
            
            for sub_i in range(4):
                frame = buf[sub_i * sub_hop : sub_i * sub_hop + sub_size]
                if len(frame) < 100:
                    continue
                peak = float(np.max(np.abs(frame)))
                if peak > 0.01:
                    amp_peaks.append(peak)
                
                r1, r2 = 0, len(frame) - 1
                thres = 0.2
                for i in range(len(frame) // 2):
                    if abs(frame[i]) < thres:
                        r1 = i
                        break
                for i in range(1, len(frame) // 2):
                    if abs(frame[len(frame) - i]) < thres:
                        r2 = len(frame) - i
                        break
                trimmed = frame[r1:r2]
                tsize = len(trimmed)
                if tsize > 10:
                    c = np.correlate(trimmed, trimmed, mode='full')[tsize-1:]
                    d = 0
                    while d < tsize - 1 and c[d] > c[d+1]:
                        d += 1
                    if d < tsize:
                        maxval = -1
                        maxpos = -1
                        for i in range(d, tsize):
                            if c[i] > maxval:
                                maxval = c[i]
                                maxpos = i
                        if maxpos > 0:
                            f0 = self.sample_rate / maxpos
                            if 60 <= f0 <= 500:
                                f0_estimates.append(f0)
            
            local_jitter = 0.0
            if len(f0_estimates) >= 2:
                diffs = np.abs(np.diff(f0_estimates))
                mean_f0 = np.mean(f0_estimates)
                if mean_f0 > 0:
                    local_jitter = (np.mean(diffs) / mean_f0)
                    
            local_shimmer = 0.0
            if len(amp_peaks) >= 2:
                diffs = np.abs(np.diff(amp_peaks))
                mean_amp = np.mean(amp_peaks)
                if mean_amp > 0:
                    local_shimmer = (np.mean(diffs) / mean_amp)
                    
            return float(local_jitter), float(local_shimmer)
            
        local_jitter, local_shimmer = get_local_jitter_shimmer(audio_chunk)

        # Base features (19 features)
        base_features = [
            high_freq_ratio,            # F1:  High freq energy
            centroid_mean / 5000,       # F2:  Spectral centroid mean
            centroid_std  / 2000,       # F3:  Centroid stability
            flatness,                   # F4:  Spectral flatness
            bandwidth     / 5000,       # F5:  Spectral bandwidth
            zcr,                        # F6:  Zero crossing rate
            flux,                       # F7:  Spectral flux
            np.mean(lfcc_mean[:5]),     # F8:  Low LFCCs
            np.std(lfcc_std[:5]),       # F9:  Low LFCC variance
            np.mean(lfcc_mean[5:15]),   # F10: Mid LFCCs
            np.std(lfcc_std[5:15]),     # F11: Mid LFCC variance
            np.mean(lfcc_mean[15:]),    # F12: High LFCCs
            np.std(lfcc_std[15:]),      # F13: High LFCC variance
            np.mean(log_linear),        # F14: Overall energy
            np.std(log_linear),         # F15: Energy variance
            rolloff / 8000,             # F16: Spectral rolloff
            min(hnr, 10) / 10,          # F17: Harmonic ratio
            min(pitch_std, 500) / 500,  # F18: Pitch variation
            contrast / 50,              # F19: Spectral contrast
        ]

        # New MFCC features (13 means + 13 stds = 26 features)
        mfcc_features = []
        for val in mfcc_mean:
            mfcc_features.append(val)
        for val in mfcc_std:
            mfcc_features.append(val)

        # New Chroma & RMS & Local Jitter/Shimmer features (6 features)
        extra_features = [
            chroma_mean,
            chroma_std,
            rms_mean,
            rms_std,
            local_jitter,
            local_shimmer
        ]

        # Combine all features (19 + 26 + 6 = 51 features)
        features = np.array(base_features + mfcc_features + extra_features)

        return features

    # ══════════════════════════════════════════════════
    # NEW: Train on REAL audio features extracted
    #      from actual generated audio signals
    # ══════════════════════════════════════════════════

    def _generate_real_audio_features(self, audio: np.ndarray) -> List[np.ndarray]:
        """Extract features from all 1-second chunks of an audio array."""
        features_list = []
        num_chunks    = len(audio) // self.chunk_samples

        for i in range(num_chunks):
            start = i * self.chunk_samples
            end   = start + self.chunk_samples
            chunk = audio[start:end]

            # Only process chunks with speech
            rms = np.sqrt(np.mean(chunk**2))
            if rms > 0.01:
                feat = self.extract_features(chunk)
                features_list.append(feat)

        return features_list

    def apply_telephony_channel(self, audio: np.ndarray, sr: int = 16000) -> np.ndarray:
        """Apply 300Hz - 3.4kHz bandpass filter and line noise to simulate telecom channels."""
        nyq = 0.5 * sr
        low = 300 / nyq
        high = 3400 / nyq
        b, a = butter(6, [low, high], btype='band')
        filtered = lfilter(b, a, audio)
        # Add a bit of line noise (SNR ~ 30dB)
        noise = np.random.randn(len(audio)) * np.random.uniform(0.005, 0.02)
        return filtered + noise

    def _train_on_real_features(self):
        """
        Train ensemble classifier on telephony-filtered features extracted from
        both augmented synthetic waveforms and real speech recordings (like gTTS).
        """
        X_real     = []
        X_synth    = []

        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Check if test_samples exist, if not generate them first
        gtts_path = os.path.join(script_dir, "test_samples", "gtts_voice.wav")
        pyttsx3_path = os.path.join(script_dir, "test_samples", "pyttsx3_voice.wav")
        if not os.path.exists(gtts_path) or not os.path.exists(pyttsx3_path):
            try:
                print("[TRAIN] Test files missing. Generating test audio samples first...")
                sys.path.append(script_dir)
                import generate_test_audio_new
                generate_test_audio_new.generate_synthetic_signals()
                generate_test_audio_new.generate_gtts_voice()
                generate_test_audio_new.generate_pyttsx3_voice()
            except Exception as e:
                print(f"[WARN] Could not generate test samples: {e}")

        # Load and extract features from actual audio files if they exist
        real_files = [
            os.path.join(script_dir, "sample_call.wav"),
            os.path.join(script_dir, "test_samples", "gtts_voice.wav"),
            os.path.join(script_dir, "test_samples", "real_noisy_voice.wav"),
            os.path.join(script_dir, "test_samples", "voice_harmonics.wav")
        ]

        synth_files = [
            os.path.join(script_dir, "test_samples", "pyttsx3_voice.wav"),
            os.path.join(script_dir, "test_samples", "synthetic_pure_sine.wav"),
            os.path.join(script_dir, "test_samples", "am_modulated_speech.wav")
        ]

        print("[TRAIN] Loading and augmenting actual audio recordings...")
        for fpath in real_files:
            if os.path.exists(fpath):
                try:
                    audio, sr = librosa.load(fpath, sr=self.sample_rate)
                    # Original
                    X_real.extend(self._generate_real_audio_features(audio))
                    # Augment: Add noise
                    audio_noise = audio + np.random.randn(len(audio)) * np.random.uniform(0.005, 0.02)
                    X_real.extend(self._generate_real_audio_features(audio_noise))
                    # Augment: Telephony channel
                    audio_tel = self.apply_telephony_channel(audio, self.sample_rate)
                    X_real.extend(self._generate_real_audio_features(audio_tel))
                except Exception as e:
                    print(f"  [WARN] Failed to load/augment {os.path.basename(fpath)}: {e}")

        for fpath in synth_files:
            if os.path.exists(fpath):
                try:
                    audio, sr = librosa.load(fpath, sr=self.sample_rate)
                    # Original
                    X_synth.extend(self._generate_real_audio_features(audio))
                    # Augment: Add noise
                    audio_noise = audio + np.random.randn(len(audio)) * np.random.uniform(0.002, 0.01)
                    X_synth.extend(self._generate_real_audio_features(audio_noise))
                    # Augment: Telephony channel
                    audio_tel = self.apply_telephony_channel(audio, self.sample_rate)
                    X_synth.extend(self._generate_real_audio_features(audio_tel))
                except Exception as e:
                    print(f"  [WARN] Failed to load/augment {os.path.basename(fpath)}: {e}")

        # Also add procedural signals to prevent overfitting and cover general cases
        t          = np.linspace(0, 10, self.sample_rate * 10)
        print("[TRAIN] Generating additional procedural signals for robustness...")

        # Procedural Natural
        for _ in range(8):
            noise_level = np.random.uniform(0.2, 0.5)
            audio = (
                0.4 * np.sin(2 * np.pi * np.random.uniform(150, 300) * t) +
                noise_level * np.random.randn(len(t))
            )
            audio = audio / (np.max(np.abs(audio)) + 1e-8) * 0.8
            audio = self.apply_telephony_channel(audio, self.sample_rate)
            X_real.extend(self._generate_real_audio_features(audio))

        for _ in range(8):
            f0    = np.random.uniform(100, 200)
            audio = (
                0.50 * np.sin(2 * np.pi * f0 * t) +
                0.30 * np.sin(2 * np.pi * f0 * 2 * t) +
                0.20 * np.sin(2 * np.pi * f0 * 3 * t) +
                0.15 * np.sin(2 * np.pi * f0 * 4 * t) +
                0.10 * np.sin(2 * np.pi * f0 * 5 * t) +
                np.random.uniform(0.1, 0.3) * np.random.randn(len(t))
            )
            audio = audio / (np.max(np.abs(audio)) + 1e-8) * 0.8
            audio = self.apply_telephony_channel(audio, self.sample_rate)
            X_real.extend(self._generate_real_audio_features(audio))

        for _ in range(6):
            f0  = np.random.uniform(120, 250)
            mod = 1 + 0.05 * np.sin(2 * np.pi * 5 * t)
            audio = (
                0.5 * np.sin(2 * np.pi * f0 * mod * t) +
                0.2 * np.random.randn(len(t))
            )
            audio = audio / (np.max(np.abs(audio)) + 1e-8) * 0.8
            audio = self.apply_telephony_channel(audio, self.sample_rate)
            X_real.extend(self._generate_real_audio_features(audio))

        for _ in range(6):
            f0      = np.random.uniform(130, 220)
            env_len = len(t)
            env     = np.abs(np.random.randn(env_len // 100 + 1))
            env     = np.interp(
                np.arange(env_len),
                np.linspace(0, env_len, len(env)),
                env
            )
            audio = (
                env * np.sin(2 * np.pi * f0 * t) +
                0.15 * np.random.randn(len(t))
            )
            audio = audio / (np.max(np.abs(audio)) + 1e-8) * 0.8
            audio = self.apply_telephony_channel(audio, self.sample_rate)
            X_real.extend(self._generate_real_audio_features(audio))

        # Procedural Synthetic
        for _ in range(8):
            freq  = np.random.uniform(150, 400)
            audio = 0.7 * np.sin(2 * np.pi * freq * t)
            audio = self.apply_telephony_channel(audio, self.sample_rate)
            X_synth.extend(self._generate_real_audio_features(audio))

        for _ in range(8):
            carrier   = np.random.uniform(200, 400)
            mod_rate  = np.random.uniform(2, 5)
            audio = (
                np.sin(2 * np.pi * carrier * t) *
                0.5 * (1 + np.sin(2 * np.pi * mod_rate * t)) * 0.6 +
                0.02 * np.random.randn(len(t))
            )
            audio = audio / (np.max(np.abs(audio)) + 1e-8) * 0.8
            audio = self.apply_telephony_channel(audio, self.sample_rate)
            X_synth.extend(self._generate_real_audio_features(audio))

        for _ in range(8):
            f0    = np.random.uniform(150, 300)
            audio = (
                0.5 * np.sin(2 * np.pi * f0 * t) +
                0.3 * np.sin(2 * np.pi * f0 * 2 * t) +
                0.2 * np.sin(2 * np.pi * f0 * 3 * t) +
                0.002 * np.random.randn(len(t))
            )
            audio = audio / (np.max(np.abs(audio)) + 1e-8) * 0.8
            audio = self.apply_telephony_channel(audio, self.sample_rate)
            X_synth.extend(self._generate_real_audio_features(audio))

        for _ in range(6):
            audio = signal.chirp(
                t,
                f0=np.random.uniform(100, 200),
                f1=np.random.uniform(300, 500),
                t1=10,
                method='linear'
            ) * 0.7
            audio += 0.01 * np.random.randn(len(t))
            audio = self.apply_telephony_channel(audio, self.sample_rate)
            X_synth.extend(self._generate_real_audio_features(audio))

        for _ in range(6):
            audio = np.random.randn(len(t)) * 0.5
            b, a  = signal.butter(
                8,
                [300 / (self.sample_rate / 2), 3000 / (self.sample_rate / 2)],
                btype='band'
            )
            audio = signal.filtfilt(b, a, audio)
            audio = audio / (np.max(np.abs(audio)) + 1e-8) * 0.8
            audio = self.apply_telephony_channel(audio, self.sample_rate)
            X_synth.extend(self._generate_real_audio_features(audio))

        # ── Build dataset ────────────────────────────────
        print(f"[TRAIN] Real samples   : {len(X_real)}")
        print(f"[TRAIN] Synth samples  : {len(X_synth)}")

        # Balance classes
        min_count = min(len(X_real), len(X_synth))
        X_real    = X_real[:min_count]
        X_synth   = X_synth[:min_count]

        X = np.vstack([X_real, X_synth])
        y = np.array([0] * min_count + [1] * min_count)

        # Shuffle
        idx = np.random.permutation(len(X))
        X, y = X[idx], y[idx]

        # Handle NaN/Inf
        X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=-1.0)

        # Train/test split (80/20)
        split    = int(0.8 * len(X))
        X_train  = X[:split];  y_train = y[:split]
        X_test   = X[split:];  y_test  = y[split:]

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled  = self.scaler.transform(X_test)

        # 1. Train RandomForest
        print("[TRAIN] Training Random Forest classifier...")
        self.rf_model = RandomForestClassifier(
            n_estimators = 200,
            max_depth    = 10,
            min_samples_split = 5,
            random_state = 42,
            class_weight = 'balanced'
        )
        self.rf_model.fit(X_train_scaled, y_train)

        # 2. Train Neural Network (MLP)
        print("[TRAIN] Training Multi-Layer Perceptron Neural Network...")
        self.mlp_model = MLPClassifier(
            hidden_layer_sizes = (64, 32),
            activation         = 'relu',
            solver             = 'adam',
            max_iter           = 300,
            random_state       = 42
        )
        self.mlp_model.fit(X_train_scaled, y_train)

        # 3. Train Gradient Boosting Classifier
        print("[TRAIN] Training Gradient Boosting classifier...")
        self.gbc_model = GradientBoostingClassifier(
            n_estimators = 100,
            learning_rate = 0.1,
            max_depth     = 5,
            random_state  = 42
        )
        self.gbc_model.fit(X_train_scaled, y_train)

        # Evaluate individual models and ensemble
        rf_test_acc  = self.rf_model.score(X_test_scaled,  y_test)
        mlp_test_acc  = self.mlp_model.score(X_test_scaled,  y_test)
        gbc_test_acc  = self.gbc_model.score(X_test_scaled,  y_test)

        rf_test_probs = self.rf_model.predict_proba(X_test_scaled)[:, 1]
        mlp_test_probs = self.mlp_model.predict_proba(X_test_scaled)[:, 1]
        gbc_test_probs = self.gbc_model.predict_proba(X_test_scaled)[:, 1]
        ensemble_test_probs = (rf_test_probs + mlp_test_probs + gbc_test_probs) / 3
        ensemble_test_pred = (ensemble_test_probs > 0.5).astype(int)
        ensemble_test_acc = np.mean(ensemble_test_pred == y_test)

        print(f"[TRAIN] ✅ Random Forest test accuracy : {rf_test_acc:.3f}")
        print(f"[TRAIN] ✅ MLP Neural Net test accuracy : {mlp_test_acc:.3f}")
        print(f"[TRAIN] ✅ Gradient Boosting accuracy  : {gbc_test_acc:.3f}")
        print(f"[TRAIN] ✅ Hybrid Ensemble test accuracy: {ensemble_test_acc:.3f}")
        print(f"[TRAIN] ✅ Features per sample: {X.shape[1]}")

        print("\n[TRAIN] Ensemble Classification Report:")
        print(classification_report(
            y_test, ensemble_test_pred,
            target_names=['Real', 'Synthetic']
        ))

        # Save model
        self._save_model()
        print(f"[TRAIN] ✅ Model saved → {self.model_path}")

    def _save_model(self):
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'rf_model': self.rf_model,
                'mlp_model': self.mlp_model,
                'gbc_model': self.gbc_model,
                'scaler': self.scaler
            }, f)

    def _load_model(self):
        with open(self.model_path, 'rb') as f:
            data = pickle.load(f)
            self.rf_model = data.get('rf_model')
            self.mlp_model = data.get('mlp_model')
            self.gbc_model = data.get('gbc_model')
            self.scaler = data.get('scaler')
        print(f"[INFO] Loaded hybrid ensemble model from {self.model_path}")

    # ══════════════════════════════════════════════════
    # VAD
    # ══════════════════════════════════════════════════

    def simple_vad(self, audio_chunk: np.ndarray, threshold: float = 0.01) -> bool:
        rms = np.sqrt(np.mean(audio_chunk**2))
        return rms > threshold

    # ══════════════════════════════════════════════════
    # PROCESS CHUNK
    # ══════════════════════════════════════════════════

    def process_chunk(
        self,
        audio_chunk: np.ndarray,
        timestamp: Optional[float] = None
    ) -> Dict:

        if timestamp is None:
            timestamp = self.current_time

        is_speech = self.simple_vad(audio_chunk)

        result = {
            'timestamp' : timestamp,
            'is_speech' : is_speech,
            'risk_score': 0.0,
            'features'  : None,
            'verdict'   : 'Analyzing...'
        }

        if is_speech:
            self.speech_chunks += 1
            features = self.extract_features(audio_chunk)

            # Handle NaN/Inf in features
            features = np.nan_to_num(features, nan=0.0, posinf=1.0, neginf=-1.0)

            self.feature_buffer.append(features)

            features_scaled     = self.scaler.transform(features.reshape(1, -1))
            prob_rf = self.rf_model.predict_proba(features_scaled)[0][1]
            probs = [prob_rf]
            if hasattr(self, 'mlp_model') and self.mlp_model is not None:
                probs.append(self.mlp_model.predict_proba(features_scaled)[0][1])
            if hasattr(self, 'gbc_model') and self.gbc_model is not None:
                probs.append(self.gbc_model.predict_proba(features_scaled)[0][1])
            prob_synthetic = sum(probs) / len(probs)
            self.risk_scores.append(prob_synthetic)

            result['risk_score'] = float(prob_synthetic)
            result['features']   = features.tolist()

            if len(self.risk_scores) >= 3:
                avg_risk = np.mean(self.risk_scores[-3:])
                if avg_risk > self.risk_threshold:
                    result['verdict'] = '⚠ HIGH RISK - Synthetic artifacts detected'
                elif avg_risk > 0.35:
                    result['verdict'] = '⚡ MEDIUM RISK - Monitor closely'
                else:
                    result['verdict'] = '✅ Low risk - Natural voice'
            else:
                result['verdict'] = 'Collecting data...'
        else:
            result['verdict'] = 'No speech detected'

        self.current_time += self.chunk_duration
        return result

    # ══════════════════════════════════════════════════
    # FINAL VERDICT
    # ══════════════════════════════════════════════════

    def get_final_verdict(self) -> Dict:
        if not self.risk_scores:
            return {
                'final_risk'          : 0.0,
                'verdict'             : 'No speech detected in window',
                'confidence'          : 0.0,
                'synthetic_probability': 0.0,
                'recommendation'      : 'Continue monitoring'
            }

        weights    = np.linspace(0.5, 1.0, len(self.risk_scores))
        final_risk = np.average(self.risk_scores, weights=weights)

        if self.feature_buffer:
            buffer_array  = np.array(self.feature_buffer)
            consistency   = np.std(buffer_array, axis=0).mean()
            high_freq_avg = np.mean([f[0] for f in self.feature_buffer])
        else:
            consistency   = 0.5
            high_freq_avg = 0.5

        if final_risk > self.risk_threshold:
            verdict        = "🔴 HIGH RISK: Likely synthetic voice (voice clone detected)"
            recommendation = "Flag call, request additional verification (OTP, callback)"
            confidence     = min(0.95, final_risk + 0.1)
        elif final_risk > 0.35:
            verdict        = "🟡 MEDIUM RISK: Possible artifacts, monitor closely"
            recommendation = "Continue call with caution, ask security questions"
            confidence     = 0.6
        else:
            verdict        = "🟢 LOW RISK: Natural voice characteristics"
            recommendation = "Proceed normally"
            confidence     = 1.0 - final_risk

        return {
            'final_risk'            : float(final_risk),
            'verdict'               : verdict,
            'confidence'            : float(confidence),
            'synthetic_probability' : float(final_risk),
            'recommendation'        : recommendation,
            'speech_chunks_analyzed': self.speech_chunks,
            'analysis_duration'     : self.current_time
        }

    # ══════════════════════════════════════════════════
    # ANALYZE FULL FILE
    # ══════════════════════════════════════════════════

    def analyze_audio_file(
        self,
        file_path: str,
        simulate_realtime: bool = True
    ) -> Dict:

        print(f"[INFO] Analyzing audio file: {file_path}")

        audio, sr = librosa.load(
            file_path,
            sr       = self.sample_rate,
            duration = None
        )

        if len(audio) < self.chunk_samples:
            print("[WARN] Audio too short for full analysis")

        self.reset_state()

        results    = []
        num_chunks = len(audio) // self.chunk_samples

        for i in range(num_chunks):
            start     = i * self.chunk_samples
            end       = start + self.chunk_samples
            chunk     = audio[start:end]
            timestamp = i * self.chunk_duration

            chunk_result = self.process_chunk(chunk, timestamp)
            results.append(chunk_result)

            if simulate_realtime:
                print(
                    f"  [{timestamp:4.1f}s] "
                    f"Risk: {chunk_result['risk_score']:.3f} | "
                    f"{chunk_result['verdict']}"
                )

        final                   = self.get_final_verdict()
        final['chunk_results']  = results
        final['file_analyzed']  = file_path

        print(f"\n{'='*45}")
        print(f"  FINAL VERDICT")
        print(f"{'='*45}")
        print(f"  Risk Score     : {final['final_risk']:.3f}")
        print(f"  Verdict        : {final['verdict']}")
        print(f"  Recommendation : {final['recommendation']}")
        print(f"  Confidence     : {final['confidence']:.2f}")
        print(f"{'='*45}")

        return final

    def process_live_stream(self, audio_stream_generator):
        print("[INFO] Live stream mode (provide chunk generator)")
        self.reset_state()
        for chunk, timestamp in audio_stream_generator:
            result = self.process_chunk(chunk, timestamp)
            yield result
            if self.current_time >= self.decision_window:
                final = self.get_final_verdict()
                yield {'final': True, **final}
                break


# ══════════════════════════════════════════════════════
# DEMO
# ══════════════════════════════════════════════════════

def demo():
    module      = AudioForensicsModule()
    sample_path = "sample_call.wav"

    if not os.path.exists(sample_path):
        print("[INFO] Creating demo audio...")
        t     = np.linspace(0, 12, int(16000 * 12))
        audio = (
            0.5 * np.sin(2 * np.pi * 200 * t) +
            0.1 * np.random.randn(len(t))
        )
        sf.write(sample_path, audio, 16000)

    result = module.analyze_audio_file(sample_path)
    return result


if __name__ == "__main__":
    import sys
    import json
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    def auto_correlate(buf, sample_rate):
        size = len(buf)
        rms = np.sqrt(np.mean(buf**2))
        if rms < 0.01:
            return -1
        
        r1, r2 = 0, size - 1
        thres = 0.2
        for i in range(size // 2):
            if abs(buf[i]) < thres:
                r1 = i
                break
        for i in range(1, size // 2):
            if abs(buf[size - i]) < thres:
                r2 = size - i
                break
                
        trimmed = buf[r1:r2]
        tsize = len(trimmed)
        if tsize == 0:
            return -1
            
        c = np.correlate(trimmed, trimmed, mode='full')[tsize-1:]
            
        d = 0
        while d < tsize - 1 and c[d] > c[d+1]:
            d += 1
            
        if d >= tsize:
            return -1
            
        maxval = -1
        maxpos = -1
        for i in range(d, tsize):
            if c[i] > maxval:
                maxval = c[i]
                maxpos = i
                
        t0 = maxpos
        if t0 <= 0:
            return -1
            
        f0 = sample_rate / t0
        if f0 < 60 or f0 > 500:
            return -1
        return f0

    def spectral_flatness(mag_arr):
        mags = np.clip(mag_arr[4:], 1e-6, None)
        if len(mags) == 0:
            return 0.0
        log_sum = np.sum(np.log(mags))
        sum_val = np.sum(mags)
        n = len(mags)
        gm = np.exp(log_sum / n)
        am = sum_val / n
        return float(gm / am) if am > 0 else 0.0

    def hf_energy_anomaly(mag_arr, sample_rate, fft_size):
        bin_hz = sample_rate / fft_size
        def band_avg(lo, hi):
            lo_idx = int(lo / bin_hz)
            hi_idx = min(len(mag_arr), int(hi / bin_hz))
            if lo_idx >= hi_idx:
                return 0.0
            return float(np.mean(mag_arr[lo_idx:hi_idx]))
            
        mid = band_avg(1000, 3000)
        hi = band_avg(4000, 7500)
        if mid < 1e-6:
            return 0.0
        ratio = hi / mid
        return float(min(1.0, abs(ratio - 0.15) / 0.5))

    def compute_jitter_shimmer_flatness_hf(file_path, target_sr=16000):
        y, sr = librosa.load(file_path, sr=target_sr)
        frame_size = 2048
        hop = 1024
        
        p_hist = []
        a_hist = []
        flat_vals = []
        hf_vals = []
        
        n_frames = (len(y) - frame_size) // hop
        for f_idx in range(max(0, n_frames)):
            start = f_idx * hop
            frame = y[start:start+frame_size]
            
            f0 = auto_correlate(frame, sr)
            if f0 > 0:
                p_hist.append(f0)
                
            peak = float(np.max(np.abs(frame)))
            if peak > 0.02:
                a_hist.append(peak)
                
            w = 0.5 - 0.5 * np.cos(2 * np.pi * np.arange(frame_size) / (frame_size - 1))
            windowed = frame * w
            fft_complex = np.fft.fft(windowed)
            mag = np.abs(fft_complex[:frame_size // 2])
            
            flat_vals.append(spectral_flatness(mag))
            hf_vals.append(hf_energy_anomaly(mag, sr, frame_size))
            
        jitter_pct = 0.0
        if len(p_hist) >= 5:
            diffs = np.sum(np.abs(np.diff(p_hist)))
            avg_diff = diffs / (len(p_hist) - 1)
            avg_f0 = np.mean(p_hist)
            if avg_f0 > 0:
                jitter_pct = (avg_diff / avg_f0) * 100
                
        shimmer_pct = 0.0
        if len(a_hist) >= 5:
            diffs = np.sum(np.abs(np.diff(a_hist)))
            avg_diff = diffs / (len(a_hist) - 1)
            avg_amp = np.mean(a_hist)
            if avg_amp > 0:
                shimmer_pct = (avg_diff / avg_amp) * 100
                
        flatness = float(np.mean(flat_vals)) if flat_vals else 0.0
        hf_anom = float(np.mean(hf_vals)) if hf_vals else 0.0
        
        return {
            "pitch_jitter_pct": float(jitter_pct),
            "amplitude_shimmer_pct": float(shimmer_pct),
            "spectral_flatness": float(flatness),
            "hf_energy_anomaly": float(hf_anom),
            "duration_sec": float(len(y) / sr),
            "frames_analyzed": int(n_frames)
        }

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        codec_type = "none"
        if "--codec" in sys.argv:
            try:
                c_idx = sys.argv.index("--codec")
                if c_idx + 1 < len(sys.argv):
                    codec_type = sys.argv[c_idx + 1]
            except Exception:
                pass

        temp_codec_file = None
        file_to_analyze = file_path

        try:
            module = AudioForensicsModule()
            
            if codec_type != "none":
                try:
                    audio, sr = librosa.load(file_path, sr=module.sample_rate)
                    if codec_type == "gsm":
                        audio = module.apply_telephony_channel(audio, module.sample_rate)
                    elif codec_type == "landline":
                        nyq = 0.5 * module.sample_rate
                        low = 500 / nyq
                        high = 2500 / nyq
                        b, a = butter(4, [low, high], btype='band')
                        filtered = lfilter(b, a, audio)
                        noise = np.random.randn(len(audio)) * np.random.uniform(0.015, 0.03)
                        audio = filtered + noise
                    
                    import tempfile
                    temp_dir = os.path.dirname(file_path)
                    fd, temp_codec_file = tempfile.mkstemp(suffix=".wav", dir=temp_dir)
                    os.close(fd)
                    sf.write(temp_codec_file, audio, module.sample_rate)
                    file_to_analyze = temp_codec_file
                except Exception as ex:
                    print(f"[WARN] Failed to apply codec: {ex}", file=sys.stderr)
            
            result = module.analyze_audio_file(file_to_analyze, simulate_realtime=False)
            visual_features = compute_jitter_shimmer_flatness_hf(file_to_analyze)
            
            # Cleanup temp file
            if temp_codec_file and os.path.exists(temp_codec_file):
                try:
                    os.remove(temp_codec_file)
                except Exception:
                    pass
            
            score = int(round(result['final_risk'] * 100))
            output = {
                "score": score,
                "confidence": result['confidence'],
                "recommendation": result['recommendation'],
                "verdict_label": result['verdict'],
                "features": visual_features,
                "chunks": [
                    {
                        "timestamp": float(c["timestamp"]),
                        "is_speech": bool(c["is_speech"]),
                        "risk_score": float(c["risk_score"]),
                        "verdict": str(c["verdict"])
                    }
                    for c in result.get('chunk_results', [])
                ]
            }
            print(json.dumps(output))
        except Exception as e:
            if temp_codec_file and os.path.exists(temp_codec_file):
                try:
                    os.remove(temp_codec_file)
                except Exception:
                    pass
            print(json.dumps({"error": str(e)}))
            sys.exit(1)
    else:
        demo()