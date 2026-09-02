#!/bin/bash
set -e
cd ~/cert-check
git pull --ff-only
npm install --omit=dev
sudo systemctl restart cert-check
echo "Deployed. Service status:"
systemctl is-active cert-check