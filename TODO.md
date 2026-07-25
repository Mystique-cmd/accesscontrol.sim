# Hash Comparison UI - Implementation Steps

## Step 1: Add `HashComparisonFrame` to `auth_gui.py`
- [x] Plan approved by user
- [x] Create the new frame with password input, compare button, and result displays
- [x] Use existing `hash_comparison.py` functions for SHA-256 and bcrypt hashing + timing
- [x] Show side-by-side results with progress bars comparing speeds

## Step 2: Register frame in `AuthGUI.__init__`
- [x] Add `HashComparisonFrame` to the frames dictionary

## Step 3: Add navigation button in `LoginFrame`
- [x] Add "Hash Comparison Demo" button to the Demo utility section

## Step 4: Add "Back to Login" button
- [x] Navigation back to login from the hash comparison frame

## Step 5: Test
- [x] Verify the app runs without import errors
- [x] All imports and classes validated

