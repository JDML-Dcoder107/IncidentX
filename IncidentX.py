import customtkinter as ctk
from tkinter import messagebox
from datetime import datetime
import sqlite3
import random
import hashlib
import re

# The customtkinter mode and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class IncidentXAppLoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("IncidentX - Login")
        self.root.geometry("450x600")
        self.root.resizable(False, False)

        # Centralizing the window
        self.center_window()

        # For the database 
        self.db_name = "incidentx.db"
        self.init_database()

        # Login UI
        self.create_login_ui()

    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def init_database(self):
        # Initializing and connecting the database
        connect = sqlite3.connect(self.db_name)
        cursor = connect.cursor()

        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS users (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       username TEXT UNIQUE NOT NULL,
                       password TEXT NOT NULL,
                       fullName TEXT NOT NULL,
                       dateRegistered TEXT NOT NULL
                       )""")
        
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS incidents (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       date TEXT NOT NULL, 
                       personType TEXT NOT NULL,
                       name TEXT NOT NULL, 
                       idNumber TEXT NOT NULL,
                       incidentType TEXT NOT NULL,
                       severity TEXT NOT NULL, 
                       description TEXT NOT NULL)
                       """)
        
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS quotes (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       quoteText TEXT NOT NULL,
                       author TEXT NOT NULL,
                       date TEXT NOT NULL)
                       """)
        connect.commit()
        connect.close()

    def hash_password(self, password):
        # Hash password using sha256
        return hashlib.sha256(password.encode()).hexdigest()
    
    def create_login_ui(self):
        # The login Interface
        main_frame = ctk.CTkFrame(self.root, corner_radius=0)
        main_frame.pack(fill="both", expand=True)

        # Logo/Title with SDG 16
        title_label = ctk.CTkLabel(
            main_frame, text="IncidentX",
            font=ctk.CTkFont(family="Times New Roman", size=36, weight="bold")
        )
        title_label.pack(pady=(40, 5))

        subtitle_Label = ctk.CTkLabel(
            main_frame,
            text="Learning Environment Monitor",
            font=ctk.CTkFont(family="Times New Roman", size=18)
        )
        subtitle_Label.pack(pady=(0, 5))

        # SDG 16 Banner Badge
        sdg16_Label = ctk.CTkLabel(main_frame,
                                   text="⚖️ Aligned with SDG: 16\nPeace, Justice and Strong Institutions",
                                   font=ctk.CTkFont(family="Times New Roman", size=16),
                                   text_color="#1F8FFF")
        sdg16_Label.pack(pady=(5, 30))

        # Login form frame
        form_frame = ctk.CTkFrame(main_frame, width=350)
        form_frame.pack(pady=20, padx=40)

        ctk.CTkLabel(
            form_frame, text="Login to your account",
            font=ctk.CTkFont(family="Times New Roman", size=22, weight="bold")
        ).pack(pady=(30, 30))

        # Username entry
        self.username_entry = ctk.CTkEntry(
            form_frame, placeholder_text="Username", width=300,
            height=45, font=ctk.CTkFont(family="Times New Roman", size=18)
        )
        self.username_entry.pack(pady=(0, 30), padx=20)

        # Password Entry
        self.password_entry = ctk.CTkEntry(
            form_frame, placeholder_text="Password", width=300, show="*",
            height=45, font=ctk.CTkFont(family="Times New Roman", size=18)
        )
        self.password_entry.pack(pady=(0, 30), padx=20)
        
        # Login Button
        login_btn = ctk.CTkButton(
            form_frame, text="LOGIN", width=300, height=45,
            command=self.login, font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold"),
            fg_color="#2ecc71", hover_color="#27ae60"   
        )
        login_btn.pack(pady=(0, 15), padx=20)

        # Register Button
        register_btn =ctk.CTkButton(
            form_frame, text="Register New User", command=self.open_register_window,
            width=300, height=40, font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold"),
            fg_color="transparent", border_width=2, border_color="#3498db"
        )
        register_btn.pack(pady=(0, 30), padx=20)

        # Bind Enter key to Login
        self.root.bind('<Return>', lambda e: self.login())

    def login(self):
        # Handle user Login
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please fill both fields.")
            return
        
        try:
            connect = sqlite3.connect(self.db_name)
            cursor = connect.cursor()

            hashed_password = self.hash_password(password)
            cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                           (username, hashed_password))
            user = cursor.fetchone()
            connect.close()

            if user:
                messagebox.showinfo("Success", f"Welcome back, {user[3]}!")
                self.root.destroy()
                self.open_main_app_window(user[3])
            else:
                messagebox.showerror("Error: Login Failed", "Invalid username or password!")
                self.password_entry.delete(0, ctk.END)

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")
        
    def open_register_window(self):
        """Open registration window"""
        RegisterWindow(self.root, self.db_name)

    def open_main_app_window(self, user_name):
        """Open the main application window after successful login"""
        root = ctk.CTk()
        IncidentXApp(root, user_name)
        root.mainloop()


class RegisterWindow:
    # Constructor and method for registration window
    def __init__(self, parent, db_name):
        self.window = ctk.CTkToplevel(parent)
        self.window.title("IncidentX - Register")  
        self.window.geometry("450x650")
        self.window.resizable(False, False)
        self.db_name = db_name

        self.center_window()
        self.create_register_ui()

    # Centralizing the window method
    def center_window(self):
        """Center the window on the screen"""
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f"{width}x{height}+{x}+{y}")

    # Hashing password method
    def hash_password(self, password):
        """Hash password using sha-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def create_register_ui(self):
        """Create the registration UI"""
        # Main Frame
        main_frame = ctk.CTkFrame(self.window, corner_radius=0)
        main_frame.pack(fill="both", expand=True)

        # Title Label
        title_Label = ctk.CTkLabel(main_frame, text="📝 Register New User", font=ctk.CTkFont(family="Times New Roman", size=32, weight="bold"))
        title_Label.pack(pady=(30, 30))    

        # Full Name Entry
        self.fullname_entry = ctk.CTkEntry(main_frame, placeholder_text="Full Name", width=350, height=45, font=ctk.CTkFont(family="Times New Roman", size=18))
        self.fullname_entry.pack(pady=(0, 15), padx=40)

        # Username Entry
        self.username_entry = ctk.CTkEntry(main_frame, placeholder_text="Username", width=350, height=45, font=ctk.CTkFont(family="Times New Roman", size=18))
        self.username_entry.pack(pady=(0, 15), padx=40)

        # Password Entry
        self.password_entry = ctk.CTkEntry(main_frame, placeholder_text="Password", show="*", width=350, height=45, font=ctk.CTkFont(family = "Times New Roman", size=18))
        self.password_entry.pack(pady=(0, 15), padx=40)

        # Confirm Password Entry
        self.confirm_password_entry = ctk.CTkEntry(main_frame, placeholder_text="Confirm Password", show="*", width=350, height=45, font=ctk.CTkFont(family="Times New Roman", size=18))
        self.confirm_password_entry.pack(pady=(0, 30), padx=40)

        # Register Button 
        register_btn = ctk.CTkButton(main_frame, text="REGISTER", width=350, height=45, command=self.register, font=ctk.CTkFont(family="Times New Roman", size=19, weight="bold"), fg_color="#2ecc71", hover_color="#27ae60")
        register_btn.pack(pady=(0, 15), padx=40)

        # Cancel Button
        cancel_btn = ctk.CTkButton(main_frame, text="CANCEL", width=350, height=45, command=self.window.destroy, font=ctk.CTkFont(family="Times New Roman", size=17, weight="bold"), fg_color="transparent", border_width=2, border_color="#95a5a6")
        cancel_btn.pack(pady=(0, 30), padx=40)

    def register(self):
        pattern_password = r'^(?=.*[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?])[\S\s]{8,16}$'
        # Handle user registration
        full_name = self.fullname_entry.get().strip()
        user_name = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()

        # Condition checking
        # Check for empty fields
        if not full_name or not user_name or not password or not confirm_password:
            messagebox.showwarning("Input Error Due to Missing Fields", "Please fill in all the required fields!")
            return 
            
        # Check the length of the username
        if len(user_name) < 4:
            messagebox.showwarning("Invalid Username", "Username must be at least more than 4 characters long!")
            return
        
        # Check password strength
        if not re.match(pattern_password, password):
            messagebox.showwarning("Weak Password", "Password must be at least 8 characters long, maximum of 16 characters, and must include at least one special character!")
            return
         
        # Check if passwords match
        if password != confirm_password:
            messagebox.showwarning("Password Mismatch", "Passwords do not match! Please try again.")
            return

        try:
            connect = sqlite3.connect(self.db_name)
            cursor = connect.cursor()

            cursor.execute("SELECT * FROM users WHERE username = ?", (user_name,))
            if cursor.fetchone():
                messagebox.showerror("Registration Error", "Username already exists")
                connect.close()
                return
            
            # Hash the password
            hashed_password = self.hash_password(password)
            cursor.execute("INSERT INTO users (username, password, fullName, dateRegistered) VALUES (?,?,?,?)",
                           (user_name, hashed_password, full_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    
            connect.commit()
            connect.close()

            messagebox.showinfo("Registration Successful", f"You have been registered successfully! You may now login with your username: {user_name}")
            self.window.destroy()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")


class IncidentXApp:
    def __init__(self, root, user_name):
        self.root = root
        self.root.title(f"IncidentX - Logged in as {user_name} | SDG 16: Peace, Justice and Strong Institutions")
        self.root.geometry("1300x800")
        self.user_name = user_name

        self.db_name = "incidentx.db"

        # SDG 16 Header
        self.create_sdg_header()

        # Create tab view
        self.tabview = ctk.CTkTabview(self.root)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Add Tabs
        self.tabview.add("📝 Report Incident")
        self.tabview.add("📊 View Records")
        self.tabview.add("💪 Motivation Corner")
        self.tabview.add("🎯 SDG 16 Dashboard")

        # Create tab contents
        self.create_report_incident_tab()
        self.create_view_records_tab()
        self.create_motivation_corner_tab()
        self.create_sdg_dashboard_tab()

    # Get a connection to the database
    def get_db_connection(self):    
        return sqlite3.connect(self.db_name)
    
    # Create sdg header
    def create_sdg_header(self):
        header_frame = ctk.CTkFrame(self.root, fg_color=("#1F8FFF", "#1565C0"), height=80)
        header_frame.pack(fill="x", padx=20, pady=(20, 10))
        header_frame.pack_propagate(False)

        # Left side - SDG info
        left_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        left_frame.pack(side="left", padx=20, fill="y")

        ctk.CTkLabel(left_frame, text="Incident X", font=ctk.CTkFont(family="Times New Roman", size=24, weight="bold"), text_color="white").pack(anchor="w", pady=(12, 0))
        ctk.CTkLabel(left_frame, text="Aligned to the SDG 16", font=ctk.CTkFont(family="Times New Roman", size=17), text_color="white").pack(anchor="w")

        # Right side - Mission Statement
        right_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        right_frame.pack(side="right", padx=20, fill="y")

        ctk.CTkLabel(right_frame, text="Our Mission: Building Safe and Inclusive Learning Environments", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold"), text_color="white").pack(anchor="e", pady=(12, 0))

        ctk.CTkLabel(right_frame, text="Promoting transparency, accountability, and well-being for all members of the educational community.", font=ctk.CTkFont(family="Times New Roman", size=15), text_color="white").pack(anchor="e")

    def create_report_incident_tab(self):
        # Create the incident report tab
        tab = self.tabview.tab("📝 Report Incident")

        # Scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(tab)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = ctk.CTkLabel(scroll_frame, text="Report New Incident", font=ctk.CTkFont(family="Times New Roman", size=32, weight="bold"))   
        title_label.pack(pady=(10, 30))

        # Form frame
        form_frame = ctk.CTkFrame(scroll_frame)
        form_frame.pack(fill="x", padx=40, pady=10)

        # Person Type
        ctk.CTkLabel(form_frame, text="Person Type", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=0, column=0, sticky="w", padx=20, pady=15)

        self.person_type_var = ctk.StringVar(value="Student")
        person_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        person_frame.grid(row=0, column=1, sticky="w", padx=20, pady=15)

        ctk.CTkRadioButton(person_frame, text="Student", variable=self.person_type_var, value="Student", font=ctk.CTkFont(family="Times New Roman", size=17)).pack(side="left", padx=10)
        ctk.CTkRadioButton(person_frame, text="Teacher", variable=self.person_type_var, value="Teacher", font=ctk.CTkFont(family="Times New Roman", size=17)).pack(side="left", padx=10)

        # Name Label and Entry
        ctk.CTkLabel(form_frame, text="Name: ", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=1, column=0, sticky="w", padx=20, pady=15)

        self.name_entry = ctk.CTkEntry(form_frame, width=400, height=40, font=ctk.CTkFont(family="Times New Roman", size=17))
        self.name_entry.grid(row=1, column=1, sticky="w", padx=20, pady=15)

        # ID Number Label and Entry
        ctk.CTkLabel(form_frame, text="ID Number: ", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=2, column=0, sticky="w", padx=20, pady=15)

        self.id_entry = ctk.CTkEntry(form_frame, width=400, height=40, font=ctk.CTkFont(family="Times New Roman", size=17))
        self.id_entry.grid(row=2, column=1, sticky="w", padx=20, pady=15)

        # Incident Type 
        ctk.CTkLabel(form_frame, text="Incident Type", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=3, column=0, sticky="w", padx=20, pady=15)

        self.incident_type_var = ctk.StringVar(value="Breakdown")
        incident_menu = ctk.CTkOptionMenu(form_frame, values=["Breakdown", "Bullying", "Vandalising", "Harassment", "Theft", "Other"], variable=self.incident_type_var, width=400, height=40, font=ctk.CTkFont(family="Times New Roman", size=17))
        incident_menu.grid(row=3, column=1, sticky="w", padx=20, pady=15)

        # Severity
        ctk.CTkLabel(form_frame, text="Severity", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=4, column=0, sticky="w", padx=20, pady=15)

        self.severity_var = ctk.StringVar(value="Low")
        severity_menu = ctk.CTkOptionMenu(form_frame, values=["Low", "Medium", "High", "Critical"], variable=self.severity_var, width=400, height=40, font=ctk.CTkFont(family="Times New Roman", size=17))
        severity_menu.grid(row=4, column=1, sticky="w", padx=20, pady=15)

        # Description Label and Textbox
        ctk.CTkLabel(form_frame, text="Description:", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=5, column=0, sticky="nw", padx=20, pady=15)

        self.description_textbox = ctk.CTkTextbox(form_frame, width=400, height=150, font=ctk.CTkFont(family="Times New Roman", size=17))
        self.description_textbox.grid(row=5, column=1, sticky="w", padx=20, pady=15)

        # Button's in the Incident Report Tab
        button_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        button_frame.grid(row=6, column=0, columnspan=2, pady=30)

        ctk.CTkButton(button_frame, text="SUBMIT REPORT", width=180, height=45, command=self.submit_incident_report, font=ctk.CTkFont(family="Times New Roman", size=19, weight="bold"), fg_color="#2ecc71", hover_color="#27ae60").pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="CLEAR FORM", width=180, height=45, font=ctk.CTkFont(family="Times New Roman", size=19, weight="bold"), fg_color="#95a5a6", hover_color="#7f8c8d", command=self.clear_incident_form).pack(side="left", padx=10)
    
    def create_view_records_tab(self):
        # Create the view records tab
        tab = self.tabview.tab("📊 View Records")

        # Title and controls frame
        header_frame = ctk.CTkFrame(tab, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(20, 10))

        ctk.CTkLabel(header_frame, text="Incident Records", font=ctk.CTkFont(family="Times New Roman", size=32, weight="bold")).pack(side="left", padx=10)
        self.stats_label = ctk.CTkLabel(header_frame, text="Total Incidents: 0", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold"))
        self.stats_label.pack(side="right", padx=10)

        # Filter frame
        filter_frame = ctk.CTkFrame(tab)
        filter_frame.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(filter_frame, text="Filter by:", font=ctk.CTkFont(family="Times New Roman", size=17, weight="bold")).pack(side="left", padx=10)

        self.filter_var = ctk.StringVar(value="All")
        filter_menu = ctk.CTkOptionMenu(filter_frame, values=["All", "Student", "Teacher", "Breakdown", "Bullying", "Vandalising", "Harassment", "Theft", "Other"], variable=self.filter_var, command=lambda x: self.refresh_records(), width=150, font=ctk.CTkFont(family="Times New Roman", size=17))
        filter_menu.pack(side="left", padx=5)

        ctk.CTkButton(filter_frame, text="🔄 Refresh", command=self.refresh_records, width=120, font=ctk.CTkFont(family="Times New Roman", size=17, weight="bold"), fg_color="#3498db", hover_color="#2980b9").pack(side="left", padx=5)
        ctk.CTkButton(filter_frame, text="✏️ Edit", command=self.edit_incident, width=100, font=ctk.CTkFont(family="Times New Roman", size=17, weight="bold"), fg_color="#f39c12", hover_color="#e67e22").pack(side="right", padx=5)
        ctk.CTkButton(filter_frame, text="🗑️ Delete", command=self.delete_incident, width=100, font=ctk.CTkFont(family="Times New Roman", size=17, weight="bold"), fg_color="#e74c3c", hover_color="#c0392b").pack(side="right", padx=5)

        # Records display frame
        records_frame = ctk.CTkScrollableFrame(tab, label_text="")
        records_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.records_container = records_frame

        # Details frame
        details_frame = ctk.CTkFrame(tab)
        details_frame.pack(fill="x", padx=20, pady=(10, 20))

        ctk.CTkLabel(details_frame, text="Incident Details", font=ctk.CTkFont(family="Times New Roman", size=20, weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))

        self.details_text = ctk.CTkTextbox(details_frame, height=100, font=ctk.CTkFont(family="Times New Roman", size=17))
        self.details_text.pack(fill="x", padx=15, pady=(0, 15))

        self.refresh_records()

    def create_motivation_corner_tab(self):
        # Create the motivation quotes tab
        tab = self.tabview.tab("💪 Motivation Corner")

        # Title
        title_frame = ctk.CTkFrame(tab, fg_color=("#f39c12", "#d35400"))
        title_frame.pack(fill="x", pady=(20, 10))

        ctk.CTkLabel(title_frame, text="Motivation & Positive Vibes Corner", font=ctk.CTkFont(family="Times New Roman", size= 30, weight="bold"), text_color="white").pack(pady=20)

        # Add quote display frame
        add_frame = ctk.CTkFrame(tab)
        add_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(add_frame, text="Add New Motivational Quote", font=ctk.CTkFont(family="Times New Roman", size=22, weight="bold")).pack(pady=(20, 15))

        ctk.CTkLabel(add_frame, text="Enter your motivational quote:", font=ctk.CTkFont(family="Times New Roman", size=17)).pack(anchor="w", padx=20)

        self.quote_textbox = ctk.CTkTextbox(add_frame, height=100, font=ctk.CTkFont(family="Times New Roman", size=17))
        self.quote_textbox.pack(fill="x", padx=20, pady=(5, 15))

        # Author Label and Entry
        ctk.CTkLabel(add_frame, text="Author (optional):", font=ctk.CTkFont(family="Times New Roman", size=17)).pack(anchor="w", padx=20)
        self.author_entry = ctk.CTkEntry(add_frame, height=40, font=ctk.CTkFont(family="Times New Roman", size=17))
        self.author_entry.pack(fill="x", padx=20, pady=(5, 20))

        ctk.CTkButton(add_frame, text="✨ Add Quote", command=self.add_quote, width=200, height=45, font=ctk.CTkFont(family="Times New Roman", size=19, weight="bold"), fg_color="#f39c12", hover_color="#e67e22").pack(pady=(0, 25))

        # Display quotes frame
        display_frame = ctk.CTkFrame(tab)
        display_frame.pack(fill="both", expand=True, padx=20, pady=(10, 20))

        header_frame = ctk.CTkFrame(display_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(20, 15), padx=20)
    
        ctk.CTkLabel(header_frame, text="Motivational Quotes Collection", font=ctk.CTkFont(family="Times New Roman", size=22, weight="bold")).pack(side="left")

        self.quote_count_label = ctk.CTkLabel(header_frame, text="Total Quotes: 0", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold"))
        self.quote_count_label.pack(side="right")

        # Quotes container
        self.quotes_container = ctk.CTkScrollableFrame(display_frame, label_text="")
        self.quotes_container.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        # Buttons
        btn_frame = ctk.CTkFrame(display_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=(10, 15))

        ctk.CTkButton(btn_frame, text="✏️ Edit Selected", command=self.edit_quote, width=140, font=ctk.CTkFont(family="Times New Roman", size=17, weight="bold"), fg_color="#f39c12", hover_color="#e67e22").pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🗑️ Delete Selected", command=self.delete_quote, width=140, font=ctk.CTkFont(family="Times New Roman", size=17, weight="bold"), fg_color="#e74c3c", hover_color="#c0392b").pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🎲 Random Quote", command=self.show_random_quote, width=140, font=ctk.CTkFont(family="Times New Roman", size=17, weight="bold"), fg_color="#9b59b6", hover_color="#8e44ad").pack(side="left", padx=5)

        self.refresh_quotes()

    def submit_incident_report(self):
        # Submit incident report method
        name = self.name_entry.get().strip()
        id_number = self.id_entry.get().strip()
        description = self.description_textbox.get("1.0", "end").strip()

        if not name or not id_number or not description:
            messagebox.showwarning("Input Error", "Please fill in all required fields!")
            return
        
        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            cursor.execute("INSERT INTO incidents (date, personType, name, idNumber, incidentType, severity, description) VALUES (?,?,?,?,?,?,?)", 
                          (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.person_type_var.get(), name, id_number, self.incident_type_var.get(), self.severity_var.get(), description))
            connect.commit()
            connect.close()

            messagebox.showinfo("Success", "Incident report submitted successfully!")
            self.clear_incident_form()
            self.refresh_records()

            # Update SDG statistics in real-time
            self.update_sdg_statistics()
        
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")

    def clear_incident_form(self):
        # Clear the incident form fields
        self.name_entry.delete(0, 'end')
        self.id_entry.delete(0, 'end')
        self.description_textbox.delete("1.0", "end")
        self.person_type_var.set("Student")
        self.incident_type_var.set("Breakdown")
        self.severity_var.set("Low")

    def refresh_records(self):
        # Refresh the records display
        # Clear existing widgets
        for widget in self.records_container.winfo_children():
            widget.destroy()

        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            filter_value = self.filter_var.get()

            if filter_value == "All":
                cursor.execute("SELECT * FROM incidents ORDER BY date DESC")
            elif filter_value in ["Student", "Teacher"]:
                cursor.execute("SELECT * FROM incidents WHERE personType = ? ORDER BY date DESC", (filter_value,))
            else:
                cursor.execute("SELECT * FROM incidents WHERE incidentType = ? ORDER BY date DESC", (filter_value,))
            
            incidents = cursor.fetchall()
            connect.close()

            # Display incidents as cards
            for incident in incidents:
                self.create_incident_card(incident)

            # Update stats label
            self.stats_label.configure(text=f"Total Incidents: {len(incidents)}")

            # Store current incidents for selection
            self.current_incidents = incidents
        
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")
    
    def create_incident_card(self, incident):
        # Create a card for each incident
        card = ctk.CTkFrame(self.records_container)
        card.pack(fill="x", padx=5, pady=5)

        # Severity color coding
        severity_colors = {
            "Low": "#2ecc71",
            "Medium": "#f1c40f",
            "High": "#e67e22",
            "Critical": "#e74c3c"
        }

        severity_color = severity_colors.get(incident[6], "#95a5a6")

        # Header frame
        header_frame = ctk.CTkFrame(card, fg_color=severity_color)
        header_frame.pack(fill="x")
        ctk.CTkLabel(header_frame, text=f"ID: {incident[0]} | {incident[5]} - {incident[6]} Severity", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold"), text_color="white").pack(side="left", padx=15, pady=10)
        ctk.CTkLabel(header_frame, text=incident[1], font=ctk.CTkFont(family="Times New Roman", size=16), text_color="white").pack(side="right", padx=15, pady=10)

        # Content
        content_frame = ctk.CTkFrame(card, fg_color="transparent")
        content_frame.pack(fill="x", padx=15, pady=10)

        info_text = f"👤 {incident[3]} ({incident[2]}) | ID: {incident[4]}"
        ctk.CTkLabel(content_frame, text=info_text, font=ctk.CTkFont(family="Times New Roman", size=17), anchor="w").pack(fill="x")

        # Button to show details
        ctk.CTkButton(card, text="View Details", command=lambda: self.show_incident_details_by_id(incident[0]), width=120, height=30, font=ctk.CTkFont(family="Times New Roman", size=16)).pack(side="right", padx=15, pady=(0, 10))

        # Store incident ID in card for selection
        card.incident_id = incident[0]

        # Click to select card
        def select_card(event):
            self.selected_incident_id = incident[0]
            self.show_incident_details_by_id(incident[0])

        card.bind("<Button-1>", select_card)

    def show_incident_details_by_id(self, incident_id):
        # Show details of incident by ID
        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            result = cursor.fetchone()
            connect.close()

            if result:
                self.selected_incident_id = incident_id
                self.details_text.delete("1.0", "end")
                self.details_text.insert("1.0", f"Description:\n{result[7]}")

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")

    def edit_incident(self):
        # Edit selected incident method
        if not hasattr(self, "selected_incident_id"):
            messagebox.showwarning("No Selection", "Please select an incident to edit!")
            return
        
        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            cursor.execute("SELECT * FROM incidents WHERE id = ?", (self.selected_incident_id,))
            incident = cursor.fetchone()
            connect.close()

            if incident:
                EditIncidentWindow(self.root, self.db_name, incident, self.refresh_records)

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")

    def delete_incident(self):
        # Delete selected incident method
        if not hasattr(self, "selected_incident_id"):
            messagebox.showwarning("No Selection", "Please select an incident to delete!")
            return
        
        if messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete this incident? This action cannot be undone."):
            try:
                connect = self.get_db_connection()
                cursor = connect.cursor()

                cursor.execute("DELETE FROM incidents WHERE id = ?", (self.selected_incident_id,))

                connect.commit()
                connect.close()

                self.refresh_records()
                messagebox.showinfo("Success", "Incident deleted successfully!")

                # Update SDG statistics in real-time
                self.update_sdg_statistics()
            
            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"An error has occurred: {e}")
        
    def add_quote(self):
        # Add a new motivational quote method
        quote = self.quote_textbox.get("1.0", "end").strip()
        author = self.author_entry.get().strip()

        if not quote:
            messagebox.showwarning("Empty Quote", "Please enter a motivational quote!")
            return
        
        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            cursor.execute("INSERT INTO quotes (quoteText, author, date) VALUES (?, ?, ?)", 
                          (quote, author if author else "Anonymous", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            connect.commit()
            connect.close()

            messagebox.showinfo("Success", "Motivational quote added successfully!")
            self.quote_textbox.delete("1.0", "end")
            self.author_entry.delete(0, "end")
            self.refresh_quotes()

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")

    def refresh_quotes(self):
        # Refresh the motivational quotes display
        for widget in self.quotes_container.winfo_children():
            widget.destroy()

        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            cursor.execute("SELECT * FROM quotes ORDER BY date DESC")
            quotes = cursor.fetchall()
            connect.close()

            # Display quotes as cards
            for quote in quotes:
                self.create_quote_card(quote)

            # Update quote count label
            self.quote_count_label.configure(text=f"Total Quotes: {len(quotes)}")

            # Store current quotes for selection
            self.current_quotes = quotes

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")    

    def create_quote_card(self, quote):
        # Create a card for each motivational quote
        card = ctk.CTkFrame(self.quotes_container)
        card.pack(fill="x", padx=5, pady=5)

        # Main content frame
        content_frame = ctk.CTkFrame(card, fg_color="transparent")
        content_frame.pack(fill="both", expand=True)

        # Quote text
        quote_label = ctk.CTkLabel(content_frame, text=f'"{quote[1]}"', font=ctk.CTkFont(family="Times New Roman", size=18), wraplength=750, anchor="w", justify="left")
        quote_label.pack(fill="x", padx=20, pady=(15, 5))

        # Bottom frame with author and buttons
        bottom_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        bottom_frame.pack(fill="x", padx=20, pady=(0, 15))

        # Author on the left
        author_label = ctk.CTkLabel(bottom_frame, text=f"- {quote[2]}", font=ctk.CTkFont(family="Times New Roman", size=16, slant="italic"))
        author_label.pack(side="left")

        # Buttons on the right 
        button_frame = ctk.CTkFrame(bottom_frame, fg_color="transparent")
        button_frame.pack(side="right")

        # Edit button 
        edit_btn = ctk.CTkButton(button_frame, text="✏️ Edit Quote", command=lambda: self.edit_quote_by_id(quote[0]), width=60, font=ctk.CTkFont(family="Times New Roman", size=16), fg_color="#f39c12", hover_color="#e67e22")
        edit_btn.pack(side="left", padx=3)

        # Delete button
        delete_btn = ctk.CTkButton(button_frame, text="🗑️ Delete Quote", command=lambda: self.delete_quote_by_id(quote[0]), width=60, font=ctk.CTkFont(family="Times New Roman", size=16), fg_color="#e74c3c", hover_color="#c0392b")
        delete_btn.pack(side="left", padx=3)

        # Random quote button
        random_btn = ctk.CTkButton(button_frame, text="🎲 Random Quote", command=self.show_random_quote, width=60, font=ctk.CTkFont(family="Times New Roman", size=16), fg_color="#9b59b6", hover_color="#8e44ad")
        random_btn.pack(side="left", padx=3)

        # Store quote ID 
        card.quote_id = quote[0]

        # Click to select card
        def select_card(event):
            self.selected_quote_id = quote[0]

        card.bind("<Button-1>", select_card)

    def edit_quote(self):
        # Edit quote 
        if not hasattr(self, "selected_quote_id"):
            messagebox.showwarning("No Selection", "Please click on a quote to select it first!")
            return
        
        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            cursor.execute("SELECT * FROM quotes WHERE id = ?", (self.selected_quote_id,))
            quote = cursor.fetchone()
            connect.close()

            if quote:
                EditQuoteWindow(self.root, self.db_name, quote, self.refresh_quotes)

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")

    def edit_quote_by_id(self, quote_id):
        # Edit quote by ID (called from card button)
        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            cursor.execute("SELECT * FROM quotes WHERE id = ?", (quote_id,))
            quote = cursor.fetchone()
            connect.close()

            if quote:
                EditQuoteWindow(self.root, self.db_name, quote, self.refresh_quotes)
        
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")

    def delete_quote(self):
        # Delete selected quote method
        if not hasattr(self, "selected_quote_id"):
            messagebox.showwarning("No Selection", "Please click on a quote to select it first!")
            return

        if messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete this quote?"):
            try:
                connect = self.get_db_connection()
                cursor = connect.cursor()

                cursor.execute("DELETE FROM quotes WHERE id = ?", (self.selected_quote_id,))    
                
                connect.commit()
                connect.close()

                self.refresh_quotes()
                messagebox.showinfo("Success", "Quote deleted successfully!")
            
            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"An error has occurred: {e}")

    def delete_quote_by_id(self, quote_id):
        # Delete quote by ID (called from card button)
        if messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete this quote?"):
            try:
                connect = self.get_db_connection()
                cursor = connect.cursor()

                cursor.execute("DELETE FROM quotes WHERE id = ?", (quote_id,))
                connect.commit()
                connect.close()

                self.refresh_quotes()
                messagebox.showinfo("Success", "Quote deleted successfully!")
            
            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"An error has occurred: {e}")

    def show_random_quote(self):
        # Show a random motivational quote
        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            cursor.execute("SELECT quoteText, author FROM quotes")
            quotes = cursor.fetchall()
            connect.close()

            if not quotes:
                messagebox.showinfo("No Quotes", "No motivational quotes available yet! Add some motivational quotes first.")
                return
            
            selected_quote = random.choice(quotes)
            messagebox.showinfo("Random Quote", f'"{selected_quote[0]}"\n\n- {selected_quote[1]}')

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")

    def create_sdg_dashboard_tab(self):
        # Create the SDG dashboard tab
        tab = self.tabview.tab("🎯 SDG 16 Dashboard")

        # Scrollable Frame
        scroll_frame = ctk.CTkScrollableFrame(tab)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_frame = ctk.CTkFrame(scroll_frame, fg_color=("#1F8FFF", "#1565C0"))
        title_frame.pack(fill="x", pady=(10, 20))

        ctk.CTkLabel(title_frame, text="🎯 SDG 16: Peace, Justice and Strong Institutions", font=ctk.CTkFont(family="Times New Roman", size=30, weight="bold"), text_color="white").pack(pady=20)

        # SDG 16 Overview
        overview_frame = ctk.CTkFrame(scroll_frame)
        overview_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(overview_frame, text="About SDG 16", font=ctk.CTkFont(family="Times New Roman", size=24, weight="bold")).pack(anchor="w", padx=20, pady=(20, 10))

        overview_text = """SDG 16 aims to promote peaceful and inclusive societies for sustainable development, provide access to justice for all, and build effective, accountable, and inclusive institutions at all levels. 
                         
In the context of educational institutions, SDG 16 focuses on:
• Creating safe, non-violent learning environments free from bullying and harassment
• Ensuring equal access to education and promoting inclusivity
• Reducing all forms of violence and related harm in schools
• Promoting the rule of law and transparent, accountable institutional practices
• Developing responsive, inclusive decision-making processes"""
        
        ctk.CTkLabel(overview_frame, text=overview_text, font=ctk.CTkFont(family="Times New Roman", size=17), justify="left", wraplength=1000).pack(anchor="w", padx=20, pady=(0, 20))

        # How the IncidentX App Align (Alignment Section Frame)
        alignment_frame = ctk.CTkFrame(scroll_frame)
        alignment_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(alignment_frame, text="How IncidentX Supports SDG 16", font=ctk.CTkFont(family="Times New Roman", size=24, weight="bold")).pack(anchor="w", padx=20, pady=(20, 10))

        # Create alignment cards
        alignments = [
            {
                "target": "16.1 - Reduce Violence Everywhere",
                "description": "This system aims to record the incidents of violence, bullying, breakdowns, and harassment within the educational institutions, helping to address and reduce such issues",
                "icon": "🛡️"
            },
            {
                "target": "16.2 - Protect Children from Abuse, Exploitation, Trafficking, and Violence",
                "description": "By providing a platform for reporting incidents, the system helps protect students from various forms of abuse and violence, ensuring a safer learning environment.",
                "icon": "👥"
            },
            {
                "target": "16.6 - Develop Effective, Accountable and Transparent Institutions",
                "description": "The system promotes transparency and accountability within educational institutions by systematically documenting incidents and responses, fostering trust among students and teachers.",
                "icon": "🏛️"
            },
            {
                "target": "16.7 - Ensure Responsive, Inclusive, and Representative Decision-Making",
                "description": "The data collected through the system can inform the guidance, or other sector of the institutions that supports the mental well being of the student and teacher providing decision-making processes, ensuring that policies and interventions are responsive to the needs of all members of the educational community.",
                "icon": "🤝"
            },
            {
                "target": "16.10 - Access to Information and Protect Fundamental Freedoms",
                "description": "The system ensures that students and teachers have access to information regarding incident reporting procedures and their rights, promoting fundamental freedoms within the educational environment.",
                "icon": "🔐"
            },
            {
                "target": "16.C - Promote and Enforce Non-Discriminatory Laws and Policies",
                "description": "The system supports the enforcement of non-discriminatory policies by providing a platform to report incidents related to discrimination, thereby fostering an inclusive and equitable educational environment.",
                "icon": "⚖️"
            }
        ]
        
        for alignment in alignments:
            card = ctk.CTkFrame(alignment_frame)
            card.pack(fill="x", padx=20, pady=8)

            # Icon and Target 
            header_frame = ctk.CTkFrame(card, fg_color=("#3498db", "#2980b9"))
            header_frame.pack(fill="x")

            ctk.CTkLabel(header_frame, text=f"{alignment['icon']} {alignment['target']}", font=ctk.CTkFont(family="Times New Roman", size=19, weight="bold"), text_color="white").pack(side="left", padx=15, pady=12)

            # Description
            ctk.CTkLabel(card, text=alignment['description'], font=ctk.CTkFont(family="Times New Roman", size=17), wraplength=900, justify="left").pack(anchor="w", padx=15, pady=15)

        # Statistics Section
        stats_frame = ctk.CTkFrame(scroll_frame)
        stats_frame.pack(fill="x", pady=20)

        ctk.CTkLabel(stats_frame, text="Impact Statistics", font=ctk.CTkFont(family="Times New Roman", size=24, weight="bold")).pack(anchor="w", pady=(20, 15), padx=20)

        # Get statistics from the database
        self.display_sdg_statistics(stats_frame)
        
        # Store stats frame reference for updates
        self.sdg_stats_frame = stats_frame
            
        # Action Items 
        action_frame = ctk.CTkFrame(scroll_frame)
        action_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(action_frame, text="SDG 16 Action Items for Educational Institutions", font=ctk.CTkFont(family="Times New Roman", size=24, weight="bold")).pack(anchor="w", padx=20, pady=(20, 10))

        actions = [
            "✓ Establish clear anti-bullying, anti-harassment and anti-violence policies",
            "✓ Implement transparent incident reporting systems (like IncidentX)",
            "✓ Provide regular training on conflict resolution and peaceful communication",
            "✓ Create support systems for affected students and teachers",
            "✓ Monitor and evaluate safety measures regularly",
            "✓ Foster a culture of respect, inclusivity, and accountability",
            "✓ Engage all stakeholders in creating safe learning environments",
            "✓ Ensure equal access to support services regardless of background"
        ]

        for action in actions:
            ctk.CTkLabel(action_frame, text=action, font=ctk.CTkFont(family="Times New Roman", size=17), anchor="w").pack(anchor="w", padx=40, pady=5)

        # Spacer
        ctk.CTkLabel(action_frame, text="").pack(pady=20)

    def display_sdg_statistics(self, parent_frame):
        # Display statistics related to SDG 16 impact
        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            # Total incidents
            cursor.execute("SELECT COUNT(*) FROM incidents")
            total_incidents = cursor.fetchone()[0]  

            # Incidents by type
            cursor.execute("SELECT incidentType, COUNT(*) FROM incidents GROUP BY incidentType") 
            incidents_by_type = cursor.fetchall()

            # Critical incidents
            cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'Critical'")
            critical_count = cursor.fetchone()[0]

            # Recent incidents (last 30 days)
            cursor.execute("SELECT COUNT(*) FROM incidents WHERE date >= date('now', '-30 days')")
            recent_count = cursor.fetchone()[0]

            connect.close()

            # Display statistics in cards
            stats_container = ctk.CTkFrame(parent_frame, fg_color="transparent")
            stats_container.pack(fill="x", padx=20, pady=(0, 20))

            # Stat cards
            self.create_stat_card(stats_container, "📋 Total Incidents", str(total_incidents), 
                                 "Total documented cases", 0)
            self.create_stat_card(stats_container, "⚠️ Critical Cases", str(critical_count), 
                                 "Requiring immediate attention", 1)
            self.create_stat_card(stats_container, "📅 Recent (30 days)", str(recent_count), 
                                 "New incidents this month", 2)
            
            # Breakdown by type
            if incidents_by_type:
                breakdown_frame = ctk.CTkFrame(parent_frame)
                breakdown_frame.pack(fill="x", padx=20, pady=10)

                ctk.CTkLabel(breakdown_frame, text="Incident Breakdown by Type", font=ctk.CTkFont(family="Times New Roman", size=19, weight="bold")).pack(anchor="w", padx=15, pady=(15, 10))
                
                for incident_type, count in incidents_by_type:
                    type_frame = ctk.CTkFrame(breakdown_frame, fg_color="transparent")
                    type_frame.pack(fill="x", padx=15, pady=2)
                    
                    ctk.CTkLabel(type_frame, text=f"• {incident_type}:", font=ctk.CTkFont(family="Times New Roman", size=17)).pack(side="left")
                    ctk.CTkLabel(type_frame, text=f"{count} cases ({round(count/total_incidents*100, 1)}%)" if total_incidents > 0 else "0 cases", font=ctk.CTkFont(family="Times New Roman", size=17, weight="bold")).pack(side="left", padx=10)

                ctk.CTkLabel(breakdown_frame, text="").pack(pady=10)
        except sqlite3.Error as e:
            ctk.CTkLabel(parent_frame, text=f"Unable to fetch statistics: {e}", font=ctk.CTkFont(family="Times New Roman", size=16), text_color="red").pack(padx=20, pady=10)
    
    def update_sdg_statistics(self):
        """Update the SDG statistics display"""
        if hasattr(self, "sdg_stats_frame"):
            # Clear existing stats
            for widget in self.sdg_stats_frame.winfo_children():
                widget.destroy()
                
            # Recreate the statistics display with updated data
            ctk.CTkLabel(
                self.sdg_stats_frame, text="Impact Statistics", font=ctk.CTkFont(family="Times New Roman", size=24, weight="bold")
            ).pack(anchor="w", padx=20, pady=(20, 15))
            self.display_sdg_statistics(self.sdg_stats_frame)
    
    def create_stat_card(self, parent, title, value, description, column):
        # Create a statistic card
        card = ctk.CTkFrame(parent)
        card.grid(row=0, column=column, padx=10, pady=10, sticky="ew")

        parent.grid_columnconfigure(column, weight=1)

        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(family="Times New Roman", size=17, weight="bold")).pack(pady=(15, 5)) 
        ctk.CTkLabel(card, text=value, font=ctk.CTkFont(family="Times New Roman", size=36, weight="bold"), text_color=("#1F8FFF", "#3498db")).pack(pady=5)
        ctk.CTkLabel(card, text=description, font=ctk.CTkFont(family="Times New Roman", size=15), text_color="gray").pack(pady=(0, 15))


# Edit Incident Class Window
class EditIncidentWindow:
    # Constructor for the Edit Incident Window
    def __init__(self, parent, db_name, incident, refresh_callback):
        self.window = ctk.CTkToplevel(parent)
        self.window.title("Edit Incident Report")
        self.window.geometry("550x650")
        self.db_name = db_name
        self.incident = incident
        self.refresh_callback = refresh_callback

        self.create_edit_ui()

    def get_db_connection(self):
        # Get database connection
        return sqlite3.connect(self.db_name)
    
    def create_edit_ui(self):
        # Create the edit Incident interface 

        # Scrollable Frame
        scroll_frame = ctk.CTkScrollableFrame(self.window)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title 
        ctk.CTkLabel(scroll_frame, text=f"✏️ Edit Incident Report (ID: {self.incident[0]})", font=ctk.CTkFont(family="Times New Roman", size=28, weight="bold")).pack(pady=(10, 30))

        # Form Frame
        form_frame = ctk.CTkFrame(scroll_frame)
        form_frame.pack(fill="x", padx=20, pady=10)
        
        # Person Type
        ctk.CTkLabel(form_frame, text="Person Type:", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=0, column=0, sticky="w", padx=20, pady=15)

        self.person_type_var = ctk.StringVar(value=self.incident[2])
        person_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        person_frame.grid(row=0, column=1, sticky="w", padx=20, pady=15)

        ctk.CTkRadioButton(person_frame, text="Student", variable=self.person_type_var, value="Student").pack(side="left", padx=10)

        ctk.CTkRadioButton(person_frame, text="Teacher", variable=self.person_type_var, value="Teacher").pack(side="left", padx=10)

        # Name 
        ctk.CTkLabel(form_frame, text="Name:", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=1, column=0, sticky="w", padx=20, pady=15)

        self.name_entry = ctk.CTkEntry(form_frame, width=350, height=40, font=ctk.CTkFont(family="Times New Roman", size=17))
        self.name_entry.insert(0, self.incident[3])
        self.name_entry.grid(row=1, column=1, sticky="w", padx=20, pady=15)

        # ID Number
        ctk.CTkLabel(form_frame, text="ID Number:", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=2, column=0, sticky="w", padx=20, pady=15)

        self.id_entry = ctk.CTkEntry(form_frame, width=350, height=40, font=ctk.CTkFont(family="Times New Roman",size=17))
        self.id_entry.insert(0, self.incident[4])
        self.id_entry.grid(row=2, column=1, sticky="w", padx=20, pady=15)

        # Incident Type 
        ctk.CTkLabel(form_frame, text="Incident Type:", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=3, column=0, sticky="w", padx=20, pady=15)

        self.incident_type_var = ctk.StringVar(value=self.incident[5])
        incident_menu = ctk.CTkOptionMenu(form_frame, values=["Breakdown", "Bullying", "Vandalising", "Harassment", "Theft", "Other"], variable=self.incident_type_var, width=350, height=40)
        incident_menu.grid(row=3, column=1, sticky="w", padx=20, pady=15)
        
        # Severity
        ctk.CTkLabel(form_frame, text="Severity Level:", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=4, column=0, sticky="w", padx=20, pady=15)

        self.severity_var = ctk.StringVar(value=self.incident[6])
        severity_menu = ctk.CTkOptionMenu(form_frame, values=["Low", "Medium", "High", "Critical"], variable=self.severity_var, width=350, height=40)
        severity_menu.grid(row=4, column=1, sticky="w", padx=20, pady=15)

        # Description
        ctk.CTkLabel(form_frame, text="Incident Description:", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).grid(row=5, column=0, sticky="nw", padx=20, pady=15)

        self.description_textbox = ctk.CTkTextbox(form_frame, width=350, height=150, font=ctk.CTkFont(family="Times New Roman", size=17))
        self.description_textbox.insert("1.0", self.incident[7])
        self.description_textbox.grid(row=5, column=1, sticky="w", padx=20, pady=15)

        # Buttons
        button_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        button_frame.grid(row=6, column=0, columnspan=2, pady=30)

        ctk.CTkButton(button_frame, text="💾 Save Changes", command=self.save_changes, width=180, height=45, font=ctk.CTkFont(family="Times New Roman", size=19, weight="bold"), fg_color="#2ecc71", hover_color="#27ae60").pack(side="left", padx=10)

        ctk.CTkButton(button_frame, text="❌ Cancel", command=self.window.destroy, width=180, height=45, font=ctk.CTkFont(family="Times New Roman", size=19, weight="bold"), fg_color="#95a5a6", hover_color="#7f8c8d").pack(side="left", padx=10)
    
    # Save changes method
    def save_changes(self):
        # Save changes to the incident report
        name = self.name_entry.get().strip()
        id_number = self.id_entry.get().strip()
        description = self.description_textbox.get("1.0", "end").strip()

        if not name or not id_number or not description:
            messagebox.showwarning("Input Error", "Please fill in all required fields!")
            return
        
        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            cursor.execute("UPDATE incidents SET personType = ?, name = ?, idNumber = ?, incidentType = ?, severity = ?, description = ? WHERE id = ?", 
                          (self.person_type_var.get(), name, id_number, self.incident_type_var.get(), self.severity_var.get(), description, self.incident[0]))

            connect.commit()
            connect.close()

            messagebox.showinfo("Success", "Incident report updated successfully!")
            self.refresh_callback()
            self.window.destroy()

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")


class EditQuoteWindow:
    # Constructor for the Edit Quote Window
    def __init__(self, parent, db_name, quote, refresh_callback):
        self.window = ctk.CTkToplevel(parent)
        self.window.title("Edit Motivational Quote")
        self.window.geometry("600x400")
        self.db_name = db_name
        self.quote = quote
        self.refresh_callback = refresh_callback

        self.create_edit_ui()

    def get_db_connection(self):
        # Get database connection
        return sqlite3.connect(self.db_name)
    
    def create_edit_ui(self):
        # Create the edit quote interface
        
        # Main frame
        main_frame = ctk.CTkFrame(self.window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        ctk.CTkLabel(main_frame, text=f"✏️ Edit Motivational Quote (ID: {self.quote[0]})", font=ctk.CTkFont(family="Times New Roman", size=28, weight="bold")).pack(pady=(20, 30))

        # Quote 
        ctk.CTkLabel(main_frame, text="Quote:", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).pack(anchor="w", padx=30, pady=(10, 5))

        self.quote_textbox = ctk.CTkTextbox(main_frame, height=150, font=ctk.CTkFont(family="Times New Roman", size=17))

        self.quote_textbox.insert("1.0", self.quote[1])
        self.quote_textbox.pack(fill="x", padx=30, pady=(0, 20))

        # Author 
        ctk.CTkLabel(main_frame, text="Author:", font=ctk.CTkFont(family="Times New Roman", size=18, weight="bold")).pack(anchor="w", padx=30, pady=(0, 5))

        self.author_entry = ctk.CTkEntry(main_frame, height=40, font=ctk.CTkFont(family="Times New Roman", size=17))
        self.author_entry.insert(0, self.quote[2])
        self.author_entry.pack(fill="x", padx=30, pady=(0, 30))

        # Buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)

        ctk.CTkButton(button_frame, text="💾 Save Changes", command=self.save_changes, width=180, height=45, font=ctk.CTkFont(family="Times New Roman", size=19, weight="bold"), fg_color="#2ecc71", hover_color="#27ae60").pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="❌ Cancel", command=self.window.destroy, width=180, height=45, font=ctk.CTkFont(family="Times New Roman", size=19, weight="bold"), fg_color="#95a5a6", hover_color="#7f8c8d").pack(side="left", padx=10)
    
    # Save changes method
    def save_changes(self):
        # Save changes to the motivational quote
        quote = self.quote_textbox.get("1.0", "end").strip()
        author = self.author_entry.get().strip()

        if not quote:
            messagebox.showwarning("Empty Quote", "Please enter a motivational quote!")
            return
        
        try:
            connect = self.get_db_connection()
            cursor = connect.cursor()

            cursor.execute("UPDATE quotes SET quoteText = ?, author = ? WHERE id = ?", 
                          (quote, author if author else "Anonymous", self.quote[0]))

            connect.commit()
            connect.close()

            messagebox.showinfo("Success", "Motivational quote updated successfully!")
            self.refresh_callback()
            self.window.destroy()

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error has occurred: {e}")


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    root = ctk.CTk()
    app = IncidentXAppLoginWindow(root)
    root.mainloop()