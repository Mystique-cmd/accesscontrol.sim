# Session Expiration & Auto-Logout Integration

## Goal
Integrate token expiration and automatic logout after inactivity into the GUI.

## Implementation

### 1. Periodic session health check in `AuthGUI` ✅
- `_check_session_health()` runs every 2 seconds via `after()`.
- Checks `ttl_remaining` and `idle_remaining` directly from session timestamps (without touching/resetting the idle timer).
- Calls `_force_logout(reason)` when either expires.

### 2. `_force_logout()` in `AuthGUI` ✅
- Cleans up session state (token, username, role).
- Shows a `messagebox.showwarning()` with the expiry reason.
- Navigates to LoginFrame.

### 3. Session countdown display on `DashboardFrame` ✅
- `_update_session_timer()` runs every 1 second.
- Displays "Session expires in Xm Ys | Idle timeout in Zs".
- Changes color to orange when idle < 10s.
- Cleaned up `_timer_job` on logout.

