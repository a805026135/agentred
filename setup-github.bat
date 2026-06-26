@echo off
chcp 65001 >nul 2>&1
echo ============================================
echo   AgentRed - GitHub Push Script
echo   Username: a805026135
echo ============================================
echo.

cd /d "%~dp0"

echo [1/4] Setting remote URL...
git remote set-url origin https://github.com/a805026135/agentred.git
echo   Done: https://github.com/a805026135/agentred.git

echo.
echo [2/4] Verify commit...
git log --oneline -1

echo.
echo ============================================
echo   NEXT STEPS - Follow these 3 steps:
echo ============================================
echo.
echo   Step 1: Create a Personal Access Token (PAT)
echo   -----------------------------------------------
echo   1. Open https://github.com/settings/tokens/new
echo   2. Note name: "AgentRed Push"
echo   3. Expiration: 30 days (or your preference)
echo   4. Select scopes: Check ONLY "repo" (full control)
echo   5. Click "Generate token"
echo   6. COPY the token (you will only see it once!)
echo.
echo   Step 2: Create the GitHub Repository
echo   -----------------------------------------------
echo   1. Open https://github.com/new
echo   2. Repository name: agentred
echo   3. Description: AI Agent security testing framework with 160+ attack cases from latest research
echo   4. Visibility: Public
echo   5. DO NOT check "Add a README file" (we already have one)
echo   6. DO NOT check "Add .gitignore" (we already have one)
echo   7. Click "Create repository"
echo.
echo   Step 3: Push your code
echo   -----------------------------------------------
echo   Run this command (replace YOUR_TOKEN with the token from Step 1):
echo.
echo   git push https://a805026135:YOUR_TOKEN@github.com/a805026135/agentred.git main
echo.
echo   Or if you prefer to enter credentials interactively:
echo   git push -u origin main
echo   (Enter username: a805026135, password: YOUR_TOKEN)
echo.
echo   ============================================
echo   Your repo will be live at:
echo   https://github.com/a805026135/agentred
echo   ============================================
echo.

echo Cleanup: Removing temporary files...
if exist gh-cli.zip del gh-cli.zip
git add .gitignore
git commit --allow-empty -m "chore: cleanup temp files" 2>nul

pause
