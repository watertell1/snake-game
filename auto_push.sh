#!/bin/bash

msg="auto update: $(date '+%Y-%m-%d %H:%M:%S')"

git add .
git commit -m "$msg"
git push origin main