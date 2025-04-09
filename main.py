from app import app  # noqa: F401

if __name__ == '__main__':
    from app import socketio
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
