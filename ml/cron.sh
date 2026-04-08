#!/bin/bash
while true; do
  docker compose --profile ml up ml
  sleep 86400
done
