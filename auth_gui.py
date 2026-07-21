"""
Experiment 13 - Graphical User Interface
------------------------------------------------
A desktop GUI (Tkinter, standard library - no extra install needed on
most systems) for the authentication system built in auth_server.py.
This lets the whole login / RBAC / MFA / lockout flow be demonstrated
live by typing values instead of reading pre-scripted console output.

Screens:
  - Login       : username, password, optional OTP
  - Register    : username, password, role, optional "enable MFA"
  - Dashboard   : shows the logged-in user's role, lets them test
                  Read/Write/Delete permission checks live (with an
                  "acting on my own file" toggle), view the audit log,
                  and log out.

Run with:
    python3 auth_gui.py
"""

import tkinter as tk
from tkinter import ttk, messagebox

import auth_server
from auth_server import LoginServer, AuthError
import mfa_otp
import database as db


class AuthGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Experiment 13 - Secure Login System")
        self.geometry("520x460")
        self.resizable(False, False)

        # Persisted backend - survives between runs of the GUI unless
        # you use the "Reset Database" button.
        self.server = LoginServer(fresh=False)

        # Current session state
        self.current_token = None
        self.current_username = None
        self.current_role = None

        container = tk.Frame(self)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (LoginFrame, RegisterFrame, DashboardFrame):
            frame = F(container, self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginFrame")

    def show_frame(self, name: str):
        frame = self.frames[name]
        frame.tkraise()
        if hasattr(frame, "on_show"):
            frame.on_show()


class LoginFrame(tk.Frame):
    def __init__(self, parent, app: AuthGUI):
        super().__init__(parent)
        self.app = app

        tk.Label(self, text="Login", font=("Helvetica", 18, "bold")).pack(pady=(30, 10))

        form = tk.Frame(self)
        form.pack(pady=10)

        tk.Label(form, text="Username:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_var = tk.StringVar()
        tk.Entry(form, textvariable=self.username_var, width=28).grid(row=0, column=1, pady=5)

        tk.Label(form, text="Password:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_var = tk.StringVar()
        tk.Entry(form, textvariable=self.password_var, show="*", width=28).grid(row=1, column=1, pady=5)

        tk.Label(form, text="OTP (if MFA enabled):").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.otp_var = tk.StringVar()
        tk.Entry(form, textvariable=self.otp_var, width=28).grid(row=2, column=1, pady=5)

        self.status_label = tk.Label(self, text="", fg="red", wraplength=440, justify="center")
        self.status_label.pack(pady=(5, 5))

        tk.Button(self, text="Login", width=20, command=self.do_login).pack(pady=5)
        tk.Button(self, text="Register new account", width=20,
                  command=lambda: app.show_frame("RegisterFrame")).pack(pady=5)

        tk.Frame(self, height=2, bd=1, relief="sunken").pack(fill="x", padx=30, pady=15)

        tk.Label(self, text="Demo utility", font=("Helvetica", 10, "italic"), fg="gray").pack()
        tk.Button(self, text="Reset Database (wipes all users/logs)",
                  command=self.reset_database, fg="darkred").pack(pady=5)

    def on_show(self):
        self.status_label.config(text="")
        self.password_var.set("")
        self.otp_var.set("")

    def do_login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        otp = self.otp_var.get().strip() or None

        if not username or not password:
            self.status_label.config(text="Username and password are required.")
            return

        try:
            token = self.app.server.login(
                username, password, otp=otp, verify_otp_fn=mfa_otp.verify_totp
            )
        except AuthError as e:
            self.status_label.config(text=str(e))
            return

        self.app.current_token = token
        self.app.current_username = username
        user_row = db.get_user(username, self.app.server.db_path)
        self.app.current_role = user_row["role"]

        self.status_label.config(text="")
        self.app.show_frame("DashboardFrame")

    def reset_database(self):
        if not messagebox.askyesno(
            "Confirm reset",
            "This will permanently delete ALL registered users and the "
            "audit log. Continue?",
        ):
            return
        self.app.server = LoginServer(fresh=True)
        messagebox.showinfo("Reset complete", "Database has been reset. Please register a new account.")


class RegisterFrame(tk.Frame):
    def __init__(self, parent, app: AuthGUI):
        super().__init__(parent)
        self.app = app

        tk.Label(self, text="Register New Account", font=("Helvetica", 18, "bold")).pack(pady=(30, 10))

        form = tk.Frame(self)
        form.pack(pady=10)

        tk.Label(form, text="Username:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_var = tk.StringVar()
        tk.Entry(form, textvariable=self.username_var, width=28).grid(row=0, column=1, pady=5)

        tk.Label(form, text="Password:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_var = tk.StringVar()
        tk.Entry(form, textvariable=self.password_var, show="*", width=28).grid(row=1, column=1, pady=5)

        tk.Label(form, text="Role:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.role_var = tk.StringVar(value="student")
        ttk.Combobox(
            form, textvariable=self.role_var, values=["student", "lecturer", "admin"],
            state="readonly", width=25,
        ).grid(row=2, column=1, pady=5)

        self.mfa_var = tk.BooleanVar(value=False)
        tk.Checkbutton(self, text="Enable Multi-Factor Authentication (TOTP)",
                        variable=self.mfa_var).pack(pady=5)

        self.status_label = tk.Label(self, text="", fg="red", wraplength=440, justify="center")
        self.status_label.pack(pady=(5, 5))

        tk.Button(self, text="Register", width=20, command=self.do_register).pack(pady=5)
        tk.Button(self, text="Back to Login", width=20,
                  command=lambda: app.show_frame("LoginFrame")).pack(pady=5)

    def on_show(self):
        self.status_label.config(text="")
        self.username_var.set("")
        self.password_var.set("")
        self.role_var.set("student")
        self.mfa_var.set(False)

    def do_register(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        role = self.role_var.get()

        if not username or not password:
            self.status_label.config(text="Username and password are required.")
            return

        mfa_secret = mfa_otp.generate_secret() if self.mfa_var.get() else None

        try:
            self.app.server.register_user(username, password, role, mfa_secret=mfa_secret)
        except AuthError as e:
            self.status_label.config(text=str(e))
            return

        if mfa_secret:
            current_code = mfa_otp.totp_now(mfa_secret)
            messagebox.showinfo(
                "MFA enabled",
                f"MFA secret for '{username}':\n\n{mfa_secret}\n\n"
                f"(In a real system this is shown once as a QR code for an "
                f"authenticator app.)\n\nYour CURRENT valid OTP right now is: "
                f"{current_code}\n(demo only - a real server never reveals this)",
            )
        else:
            messagebox.showinfo("Registered", f"Account '{username}' created as {role}.")

        self.app.show_frame("LoginFrame")


class DashboardFrame(tk.Frame):
    def __init__(self, parent, app: AuthGUI):
        super().__init__(parent)
        self.app = app

        self.welcome_label = tk.Label(self, text="", font=("Helvetica", 16, "bold"))
        self.welcome_label.pack(pady=(20, 5))

        self.role_label = tk.Label(self, text="", font=("Helvetica", 11), fg="gray")
        self.role_label.pack(pady=(0, 15))

        tk.Label(self, text="Test a permission check:", font=("Helvetica", 12, "bold")).pack()

        action_frame = tk.Frame(self)
        action_frame.pack(pady=10)

        tk.Label(action_frame, text="Action:").grid(row=0, column=0, padx=5, sticky="e")
        self.action_var = tk.StringVar(value="read")
        ttk.Combobox(
            action_frame, textvariable=self.action_var,
            values=["read", "write", "delete"], state="readonly", width=15,
        ).grid(row=0, column=1, padx=5)

        self.owner_var = tk.BooleanVar(value=False)
        tk.Checkbutton(action_frame, text="Acting on MY OWN file",
                        variable=self.owner_var).grid(row=0, column=2, padx=10)

        tk.Button(self, text="Check Permission", command=self.check_permission).pack(pady=10)

        self.result_label = tk.Label(self, text="", font=("Helvetica", 13, "bold"))
        self.result_label.pack(pady=5)

        tk.Frame(self, height=2, bd=1, relief="sunken").pack(fill="x", padx=30, pady=15)

        button_row = tk.Frame(self)
        button_row.pack(pady=5)
        tk.Button(button_row, text="View Audit Log", width=18,
                  command=self.view_audit_log).grid(row=0, column=0, padx=5)
        tk.Button(button_row, text="Logout", width=18,
                  command=self.do_logout).grid(row=0, column=1, padx=5)

    def on_show(self):
        self.welcome_label.config(text=f"Welcome, {self.app.current_username}")
        self.role_label.config(
            text=f"Role: {self.app.current_role}   |   "
                 f"Permissions - Read: all, Write: "
                 f"{'own files' if self.app.current_role == 'student' else 'all'}, "
                 f"Delete: {'no' if self.app.current_role == 'student' else ('own only' if self.app.current_role == 'lecturer' else 'all')}"
        )
        self.result_label.config(text="")

    def check_permission(self):
        action = self.action_var.get()
        is_owner = self.owner_var.get()

        allowed = self.app.server.check_permission(self.app.current_token, action, is_owner=is_owner)

        if allowed:
            self.result_label.config(text=f"✓ ALLOWED: {action} (owner={is_owner})", fg="green")
        else:
            self.result_label.config(text=f"✗ DENIED: {action} (owner={is_owner})", fg="red")

    def view_audit_log(self):
        rows = db.get_audit_log(self.app.server.db_path)

        win = tk.Toplevel(self)
        win.title("Audit Log")
        win.geometry("640x360")

        columns = ("time", "user", "action", "result", "detail")
        tree = ttk.Treeview(win, columns=columns, show="headings")
        for col, width in zip(columns, (90, 90, 160, 80, 200)):
            tree.heading(col, text=col.capitalize())
            tree.column(col, width=width)
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        for r in rows:
            tree.insert("", "end", values=(
                f"{r['timestamp']:.1f}", r["username"] or "-", r["action"], r["result"], r["detail"] or "",
            ))

    def do_logout(self):
        self.app.server.logout(self.app.current_token)
        self.app.current_token = None
        self.app.current_username = None
        self.app.current_role = None
        self.app.show_frame("LoginFrame")


def main():
    app = AuthGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
