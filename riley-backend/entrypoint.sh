#!/bin/sh
# Strip asyncpg-incompatible params from DATABASE_URL before app starts
if [ -n "$DATABASE_URL" ]; then
    # Fix driver prefix
    DATABASE_URL=$(echo "$DATABASE_URL" | sed 's|^postgresql://|postgresql+asyncpg://|' | sed 's|^postgres://|postgresql+asyncpg://|')
    # Strip bad query params
    DATABASE_URL=$(echo "$DATABASE_URL" | sed 's/[?&]sslmode=[^&]*//g')
    DATABASE_URL=$(echo "$DATABASE_URL" | sed 's/[?&]channel_binding=[^&]*//g')
    # Clean up dangling ? or &
    DATABASE_URL=$(echo "$DATABASE_URL" | sed 's/[?&]$//')
    export DATABASE_URL
fi
exec "$@"
