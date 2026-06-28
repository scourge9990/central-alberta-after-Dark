#!/bin/sh
# Use Railway's PORT if set, otherwise default to 8080
export PORT=${PORT:-8080}
exec node server.js
