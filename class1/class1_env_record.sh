#!/usr/bin/env bash
# class1 env record (run inside 2026-Aug-01 P4 tutorials VM)
# usage: bash class1_env_record.sh
set -u
OUT="$HOME/class1"
mkdir -p "$OUT"
F="$OUT/environment.txt"
{
  echo "RECORD_DATE=$(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "ARCH=$(uname -m)"
  echo "OS=$(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2- | tr -d '\"')"
  echo "P4C=$(p4c --version 2>&1)"
  echo "SIMPLE_SWITCH_GRPC=$(simple_switch_grpc --version 2>&1)"
  echo "PYTHON=$(python3 --version 2>&1)"
  echo "VIRT=$(systemd-detect-virt 2>&1)"
} | tee "$F"
echo "saved: $F"