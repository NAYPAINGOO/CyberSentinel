"""Loopback-only local WSGI server; no debug mode."""
from waitress import serve
from sentinel import create_app
if __name__ == '__main__':
    serve(create_app(), host='127.0.0.1', port=8000, threads=4)
