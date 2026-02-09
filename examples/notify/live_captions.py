#!/usr/bin/env python3
"""
Live Speech-to-Text Captions on Even G2 Glasses

Records audio from your laptop mic, transcribes with Whisper,
and displays the text on your G2 glasses in real-time.

Usage:
    python live_captions.py                    # Default: record 5s chunks
    python live_captions.py --duration 10      # 10s chunks
    python live_captions.py --model base       # Larger model (more accurate)
    python live_captions.py --continuous       # Keep listening in a loop
"""

import argparse
import asyncio
import sys

import numpy as np
import sounddevice as sd
import whisper


# =============================================================================
# Audio Recording & Transcription
# =============================================================================

def record_audio_sync(duration, sample_rate=16000):
    """Record audio from default mic (blocking). Returns numpy array."""
    audio = sd.rec(int(duration * sample_rate), samplerate=sample_rate,
                   channels=1, dtype='float32')
    sd.wait()
    rms = np.sqrt(np.mean(audio ** 2))
    if rms < 0.005:
        return None, rms
    return audio.flatten(), rms


def transcribe_sync(model, audio):
    """Transcribe audio using Whisper (blocking). Returns text."""
    result = model.transcribe(audio, fp16=False, language="en")
    return result["text"].strip()


# =============================================================================
# Main
# =============================================================================

async def run(args):
    import concurrent.futures
    import subprocess
    import os

    # Load Whisper model
    print(f"Loading Whisper model '{args.model}'...")
    model = whisper.load_model(args.model)
    print("Model loaded!\n")

    print("=" * 50)
    print("LIVE CAPTIONS - Speak into your laptop mic!")
    print("Text will appear on your G2 glasses.")
    if args.continuous:
        print("Press Ctrl+C to stop.")
    print("=" * 50)
    print()

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    loop = asyncio.get_event_loop()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    notify_py = os.path.join(script_dir, "notify.py")
    python = sys.executable

    while True:
        # Step 1: Record audio
        print(f"  Listening for {args.duration}s... ", end="", flush=True)
        audio, rms = await loop.run_in_executor(
            executor, record_audio_sync, args.duration)
        print(f"(RMS: {rms:.4f})", end=" ")

        if audio is None:
            print("- silence")
            if not args.continuous:
                break
            continue

        print("- got audio!")

        # Step 2: Transcribe
        print("  Transcribing... ", end="", flush=True)
        text = await loop.run_in_executor(executor, transcribe_sync, model, audio)

        if not text or text in ("", ".", "you", "Thank you.",
                                "Thanks for watching!",
                                "Thank you for watching."):
            print(f"(noise/filler: \"{text}\")\n")
            if not args.continuous:
                break
            continue

        print(f"\"{text}\"")

        # Step 3: Send via notify.py (proven working)
        print("  Sending to glasses via notify.py...")
        result = subprocess.run(
            [python, notify_py, text],
            capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"  -> Displayed!\n")
        else:
            print(f"  -> Error: {result.stderr.strip()}\n")

        if not args.continuous:
            break

    print("Done!")


def main():
    parser = argparse.ArgumentParser(description="Live speech-to-text captions on G2 glasses")
    parser.add_argument("--duration", "-d", type=float, default=5,
                        help="Recording duration per chunk in seconds (default: 5)")
    parser.add_argument("--model", "-m", default="tiny",
                        choices=["tiny", "base", "small", "medium"],
                        help="Whisper model size (default: tiny, fastest)")
    parser.add_argument("--continuous", "-c", action="store_true",
                        help="Keep listening in a loop until Ctrl+C")

    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
