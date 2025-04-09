import multiprocessing

# Server socket
bind = "0.0.0.0:10000"
backlog = 2048

# Worker processes
workers = 1  # Use only one worker for WebSocket support
worker_class = 'sync'
worker_connections = 1000
timeout = 60
keepalive = 5
graceful_timeout = 30

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Process naming
proc_name = 'blazer'

# SSL
keyfile = None
certfile = None

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Spew
spew = False

# Server hooks
def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def pre_fork(server, worker):
    pass

def pre_exec(server):
    server.log.info("Forked child, re-executing.")

def when_ready(server):
    server.log.info("Server is ready. Spawning workers")

def worker_int(worker):
    worker.log.info("worker received INT or QUIT signal")

def worker_abort(worker):
    worker.log.info("worker received SIGABRT signal")

# WebSocket specific settings
keepalive = 5
worker_class = 'sync'
worker_connections = 1000
timeout = 60
graceful_timeout = 30
max_requests = 1000
max_requests_jitter = 50 