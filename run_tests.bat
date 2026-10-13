@echo off
echo ========================================================
echo   VEYLIX - Running Complete Automated Test Suite
echo ========================================================
echo.
echo [1/2] Running Risk Engine Tests (Milestone 3)...
python backend\tests\test_engine.py
echo.
echo [2/2] Running Human Explainability Tests (Milestone 4)...
python backend\tests\test_explanations.py
echo.
echo ========================================================
echo   All Test Suites Completed!
echo ========================================================
pause
