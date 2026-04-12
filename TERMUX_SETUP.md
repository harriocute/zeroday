# ZERODAY — Termux Setup & GitHub Push Guide
# Run these commands in Termux on your Android device

## ── STEP 1: Install required packages ──────────────────────────
pkg update && pkg upgrade -y
pkg install git -y
pkg install gh -y          # GitHub CLI (for easy auth)

## ── STEP 2: Configure Git identity ─────────────────────────────
git config --global user.name "YourName"
git config --global user.email "you@example.com"

## ── STEP 3: Authenticate with GitHub ───────────────────────────
gh auth login
# Choose: GitHub.com → HTTPS → Login with browser
# Follow the one-time code prompt in your browser

## ── STEP 4: Create the GitHub repo ─────────────────────────────
gh repo create zeroday --public --description "AI Antivirus for Android"
# This creates https://github.com/YOURUSERNAME/zeroday

## ── STEP 5: Move the project to Termux home ─────────────────────
# First, copy the unzipped zeroday/ folder to Termux storage.
# If you downloaded the zip to /sdcard/Download/:
cp -r /sdcard/Download/zeroday ~/zeroday

## ── STEP 6: Init git and push ───────────────────────────────────
cd ~/zeroday
git init
git add .
git commit -m "Initial commit: Zeroday AI Antivirus v1.0"
git branch -M main
git remote add origin https://github.com/YOURUSERNAME/zeroday.git
git push -u origin main

## ── STEP 7: Watch GitHub Actions build your APK ────────────────
# Open in browser:
# https://github.com/YOURUSERNAME/zeroday/actions
#
# The workflow "Build Zeroday APK" will trigger automatically.
# Build takes ~3–5 minutes.
# When done → click the workflow run → scroll to "Artifacts"
# Download: zeroday-debug-apk
# Install it on your device!

## ── SUBSEQUENT PUSHES (after edits) ────────────────────────────
cd ~/zeroday
git add .
git commit -m "Your change description"
git push
# GitHub Actions rebuilds APK automatically on every push

## ── TIPS ────────────────────────────────────────────────────────
# Check build status from Termux:
gh run list --repo YOURUSERNAME/zeroday

# Download latest APK directly to Termux:
gh run download --repo YOURUSERNAME/zeroday --name zeroday-debug-apk
