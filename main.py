from whispertls.WhisperTLS import WhisperTLS
import locale

if __name__ == "__main__":
    whisper = None
    try:
        locale.setlocale(locale.LC_ALL, "")
        whisper = WhisperTLS()
        whisper.start()
    except KeyboardInterrupt:
        whisper.display_error("KeyboardInterrupt An error occurred")
    finally:
        if whisper and whisper.is_running:
            whisper.shutdown()
