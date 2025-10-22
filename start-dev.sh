#!/bin/bash

# Build the editor-ext package first (required for other packages)
echo "Building editor-ext package..."

pnpm install --no-frozen-lockfile

pnpm nx run editor-ext:build

# Run database migrations
echo "Running database migrations..."
pnpm nx run server:migration:latest

# Start client and server in parallel
echo "Starting development servers..."
pnpm nx run server:start:dev &
pnpm nx run client:dev --host  &

# Wait for both processes
wait
