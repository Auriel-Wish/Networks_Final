import struct
import sys
import os
import socket
import select
import time 
import json
import ssl
import socket

BUFFER_SIZE = 4096
PORT = 1025
TIMEOUT = 60
CACHE_SIZE = 10