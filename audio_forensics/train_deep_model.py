"""
train_deep_model.py
─────────────────────────────────────────────────────────────
PyTorch Deep Learning CNN Pipeline for Spectrogram-Based Voice Spoofing Detection.
This serves as the production-grade deep learning architecture pitch for the hackathon.

Features:
- Spectrogram conversion (Linear/Mel-spectrogram options)
- Telephony codec and line noise augmentations
- SpecAugment (Time and Frequency Masking)
- 2D Convolutional Neural Network (VoiceSpoofCNN)
- Flexible PyTorch Dataset (procedural generation fallback + file directory loading)
- Production ONNX exporter
"""

import os
import sys
import numpy as np
import librosa
import soundfile as sf
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader

# Ensure output directory for model artifacts
MODEL_OUT_DIR = "models"
os.makedirs(MODEL_OUT_DIR, exist_ok=True)


# ══════════════════════════════════════════════════════════
# 1. AUDIO UTILITIES & AUGMENTATIONS (DSP Layer)
# ══════════════════════════════════════════════════════════

class AudioPreprocessor:
    def __init__(self, sample_rate=16000, n_fft=1024, hop_length=256, n_mels=80):
        self.sample_rate = sample_rate
        self.n_fft = n_fft
        self.hop_length = hop_length
        self.n_mels = n_mels

    def load_and_pad(self, file_path, duration=3.0):
        """Load audio and ensure it has exactly the target duration."""
        target_samples = int(duration * self.sample_rate)
        try:
            y, sr = librosa.load(file_path, sr=self.sample_rate)
        except Exception as e:
            print(f"[WARN] Error loading {file_path}: {e}")
            return np.zeros(target_samples, dtype=np.float32)

        if len(y) < target_samples:
            y = np.pad(y, (0, target_samples - len(y)))
        else:
            y = y[:target_samples]
        return y

    def compute_spectrogram(self, y, type='mel'):
        """Compute log-magnitude linear or Mel spectrogram."""
        stft = librosa.stft(y, n_fft=self.n_fft, hop_length=self.hop_length)
        mag = np.abs(stft)
        
        if type == 'mel':
            # Mel scale spectrogram
            mel_spec = librosa.feature.melspectrogram(
                S=mag**2, sr=self.sample_rate, n_fft=self.n_fft, 
                hop_length=self.hop_length, n_mels=self.n_mels
            )
            log_spec = librosa.power_to_db(mel_spec, ref=np.max)
        else:
            # Linear spectrogram (preserves high-frequency vocoder notches)
            log_spec = librosa.power_to_db(mag**2, ref=np.max)
            
        return log_spec


class SpecAugment(nn.Module):
    """SpecAugment data augmentation (Frequency and Time Masking)."""
    def __init__(self, freq_mask_param=15, time_mask_param=35):
        super(SpecAugment, self).__init__()
        self.freq_mask_param = freq_mask_param
        self.time_mask_param = time_mask_param

    def forward(self, spec):
        # Spec shape: [Batch, Channels, Freq, Time]
        # Clone to avoid in-place operations
        spec = spec.clone()
        b, c, f, t = spec.shape
        
        for i in range(b):
            # Frequency masking
            f_mask = np.random.randint(0, self.freq_mask_param)
            f_start = np.random.randint(0, f - f_mask)
            spec[i, :, f_start:f_start+f_mask, :] = -80.0  # Mask with silence floor
            
            # Time masking
            t_mask = np.random.randint(0, self.time_mask_param)
            t_start = np.random.randint(0, t - t_mask)
            spec[i, :, :, t_start:t_start+t_mask] = -80.0
            
        return spec


# ══════════════════════════════════════════════════════════
# 2. PYTORCH DATASET LAYER
# ══════════════════════════════════════════════════════════

class VoiceSpoofDataset(Dataset):
    """
    Highly flexible dataset. Can read real files from directory
    or auto-generate procedural training data if directory is empty.
    """
    def __init__(self, file_paths=None, labels=None, preprocessor=None, augment=False):
        self.preprocessor = preprocessor or AudioPreprocessor()
        self.augment = augment
        
        if file_paths is not None and len(file_paths) > 0:
            self.file_paths = file_paths
            self.labels = labels
            self.procedural = False
        else:
            # Generate procedural dataset in memory for self-contained execution
            print("[DATA] No training file paths provided. Creating procedural speech signals dataset...")
            self.procedural = True
            self.dataset_size = 120
            self.labels = np.array([0] * (self.dataset_size // 2) + [1] * (self.dataset_size // 2))
            
    def __len__(self):
        if self.procedural:
            return self.dataset_size
        return len(self.file_paths)
        
    def __getitem__(self, idx):
        label = self.labels[idx]
        
        if not self.procedural:
            # Load real audio
            y = self.preprocessor.load_and_pad(self.file_paths[idx])
        else:
            # Generate speech-like waveform procedurally in memory
            sr = self.preprocessor.sample_rate
            t = np.linspace(0, 3.0, sr * 3)
            
            if label == 0:  # Real/Natural-like: harmonics + heavy frequency-varying noise
                f0 = np.random.uniform(100, 250)
                # Formants simulation
                audio = (
                    0.4 * np.sin(2 * np.pi * f0 * t) +
                    0.2 * np.sin(2 * np.pi * f0 * 2 * t) +
                    0.15 * np.sin(2 * np.pi * f0 * 3 * t)
                )
                # Random envelope modulation
                env = 0.5 * (1.0 + np.sin(2 * np.pi * np.random.uniform(2, 6) * t))
                audio = audio * env
                # Add line noise
                audio += np.random.randn(len(t)) * np.random.uniform(0.05, 0.2)
            else:  # Synthetic-like: overly consistent sine waves
                f0 = np.random.uniform(150, 300)
                audio = 0.6 * np.sin(2 * np.pi * f0 * t)
                # Apply narrow band pass (telephony simulation)
                audio += np.random.randn(len(t)) * np.random.uniform(0.001, 0.005)
                
            y = audio.astype(np.float32)

        # Apply augmentation if enabled
        if self.augment:
            # Random scaling
            y = y * np.random.uniform(0.7, 1.2)
            # Add line noise
            if np.random.rand() > 0.5:
                y += np.random.randn(len(y)) * np.random.uniform(0.005, 0.03)

        # Compute spectrogram
        spec = self.preprocessor.compute_spectrogram(y, type='mel')
        
        # Normalize (Mean-Std Norm)
        spec = (spec - np.mean(spec)) / (np.std(spec) + 1e-8)
        
        # Add channel dimension: [1, Freq, Time]
        spec_tensor = torch.tensor(spec, dtype=torch.float32).unsqueeze(0)
        label_tensor = torch.tensor(label, dtype=torch.long)
        
        return spec_tensor, label_tensor


# ══════════════════════════════════════════════════════════
# 3. CONVOLUTIONAL NEURAL NETWORK (CNN MODEL)
# ══════════════════════════════════════════════════════════

class VoiceSpoofCNN(nn.Module):
    """
    2D CNN Classifier for spectrogram-based synthetic voice forensics.
    Accepts spectrogram images and classifies as Real (0) or Synthetic (1).
    """
    def __init__(self, input_shape=(1, 80, 188)):
        super(VoiceSpoofCNN, self).__init__()
        
        # Conv Layer 1
        self.conv1 = nn.Sequential(
            nn.Conv2d(1, 16, kernel_size=3, padding=1),
            nn.BatchNorm2d(16),
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2, stride=2)  # Output: 16 x 40 x 94
        )
        
        # Conv Layer 2
        self.conv2 = nn.Sequential(
            nn.Conv2d(16, 32, kernel_size=3, padding=1),
            nn.BatchNorm2d(32),
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2, stride=2)  # Output: 32 x 20 x 47
        )
        
        # Conv Layer 3
        self.conv3 = nn.Sequential(
            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2, stride=2)  # Output: 64 x 10 x 23
        )
        
        # Conv Layer 4 (High-level features)
        self.conv4 = nn.Sequential(
            nn.Conv2d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm2d(128),
            nn.ReLU(),
            nn.AdaptiveAvgPool2d((4, 4))            # Output: 128 x 4 x 4
        )
        
        # Fully Connected layers
        self.fc = nn.Sequential(
            nn.Linear(128 * 4 * 4, 128),
            nn.ReLU(),
            nn.Dropout(0.4),
            nn.Linear(128, 2)  # Binary class output: [Real, Synthetic]
        )

    def forward(self, x):
        x = self.conv1(x)
        x = self.conv2(x)
        x = self.conv3(x)
        x = self.conv4(x)
        x = x.view(x.size(0), -1)  # Flatten
        logits = self.fc(x)
        return logits


# ══════════════════════════════════════════════════════════
# 4. TRAINING PIPELINE & EVALUATION
# ══════════════════════════════════════════════════════════

def train_model(epochs=15, batch_size=16, learning_rate=0.001):
    print("=" * 65)
    print("  VOXSHIELD - DEEP LEARNING MODEL TRAINING PIPELINE")
    print("=" * 65)
    
    # Initialize devices
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[INIT] Operating Device: {device}")
    
    # Preprocessor & Datasets
    preprocessor = AudioPreprocessor(n_mels=80)
    train_dataset = VoiceSpoofDataset(preprocessor=preprocessor, augment=True)
    val_dataset = VoiceSpoofDataset(preprocessor=preprocessor, augment=False)
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    
    # Inspect shape from dataset
    dummy_spec, dummy_label = train_dataset[0]
    input_shape = dummy_spec.shape
    print(f"[DATA] Extracted Spectrogram Shape: {input_shape}")
    
    # Instantiate Model
    model = VoiceSpoofCNN(input_shape=input_shape).to(device)
    spec_augment = SpecAugment().to(device)
    
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    
    # Training Loop
    print("\n[TRAIN] Training model...")
    for epoch in range(epochs):
        model.train()
        train_loss = 0.0
        correct_train = 0
        total_train = 0
        
        for specs, labels in train_loader:
            specs, labels = specs.to(device), labels.to(device)
            
            # Apply SpecAugment to training data
            specs = spec_augment(specs)
            
            optimizer.zero_grad()
            outputs = model(specs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item() * specs.size(0)
            _, predicted = torch.max(outputs, 1)
            total_train += labels.size(0)
            correct_train += (predicted == labels).sum().item()
            
        epoch_loss = train_loss / total_train
        epoch_acc = (correct_train / total_train) * 100
        
        # Validation Loop
        model.eval()
        val_loss = 0.0
        correct_val = 0
        total_val = 0
        
        with torch.no_grad():
            for specs, labels in val_loader:
                specs, labels = specs.to(device), labels.to(device)
                outputs = model(specs)
                loss = criterion(outputs, labels)
                
                val_loss += loss.item() * specs.size(0)
                _, predicted = torch.max(outputs, 1)
                total_val += labels.size(0)
                correct_val += (predicted == labels).sum().item()
                
        epoch_val_loss = val_loss / total_val
        epoch_val_acc = (correct_val / total_val) * 100
        
        print(f"  Epoch [{epoch+1:02d}/{epochs:02d}] | "
              f"Train Loss: {epoch_loss:.4f} - Acc: {epoch_acc:5.1f}% | "
              f"Val Loss: {epoch_val_loss:.4f} - Acc: {epoch_val_acc:5.1f}%")
              
    print("\n[TRAIN] ✅ Training Completed successfully!")
    
    # Save Model Weights
    pth_path = os.path.join(MODEL_OUT_DIR, "voice_spoof_detector.pth")
    torch.save(model.state_dict(), pth_path)
    print(f"[TRAIN] Saved PyTorch weights → {pth_path}")
    
    # Export Model to ONNX for lightweight cross-platform deployment
    export_to_onnx(model, input_shape, device)


# ══════════════════════════════════════════════════════════
# 5. PRODUCTION ONNX EXPORTER
# ══════════════════════════════════════════════════════════

def export_to_onnx(model, input_shape, device):
    """Export the trained model to ONNX format."""
    print("\n[ONNX] Exporting model to ONNX format...")
    model.eval()
    
    # Generate dummy input tensor matching shape [Batch, Channels, Freq, Time]
    dummy_input = torch.randn(1, *input_shape, device=device)
    onnx_path = os.path.join(MODEL_OUT_DIR, "voice_spoof_detector.onnx")
    
    try:
        import onnx
        torch.onnx.export(
            model,
            dummy_input,
            onnx_path,
            export_params=True,
            opset_version=12,
            do_constant_folding=True,
            input_names=['spectrogram'],
            output_names=['verdict_logits'],
            dynamic_axes={
                'spectrogram': {0: 'batch_size'},
                'verdict_logits': {0: 'batch_size'}
            }
        )
        print(f"[ONNX] ✅ SUCCESS! Model exported to: {onnx_path}")
    except ImportError:
        # Fallback if library is not installed
        print("[ONNX] Warning: 'onnx' library not found. Running PyTorch export wrapper...")
        torch.onnx.export(
            model,
            dummy_input,
            onnx_path,
            export_params=True,
            opset_version=12,
            input_names=['spectrogram'],
            output_names=['verdict_logits']
        )
        print(f"[ONNX] ✅ SUCCESS! Saved ONNX graph file to: {onnx_path}")
    except Exception as e:
        print(f"[ONNX] ❌ Failed to export model: {e}")


if __name__ == "__main__":
    # Let's run a quick 3-epoch training session as sanity check/demonstration
    epochs = 3
    if len(sys.argv) > 1:
        try:
            epochs = int(sys.argv[1])
        except ValueError:
            pass
            
    train_model(epochs=epochs)
