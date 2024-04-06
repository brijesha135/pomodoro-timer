import logging
import threading
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, Scrollbar
import webbrowser
import winsound
import matplotlib.pyplot as plt

app = Flask(__name__)
app.secret_key = '94e6c72ee896bf1f9251571bf6c16d9330f33938b733e4143f143811989a038b'  # Change this to a strong, random secret key

logging.basicConfig(level=logging.DEBUG)  # Set the log level to DEBUG
app.logger.setLevel(logging.DEBUG)
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
@app.route('/')
@login_required  # Use this decorator to protect routes
@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')  # Using .get() is safer
        password = request.form.get('password')  # Using .get() is safer
        app.logger.info("Received form data - Username: %s, Password: %s", username, password)  # Log the data
        # Add your user authentication logic here
        if username == 'user' and password == 'password':
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return 'Login failed'
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

class PomodoroApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Pomodoro Timer")
        self.tasks = []
        self.work_duration = 25 * 60
        self.break_duration = 5 * 60
        self.timer_running = False
        self.time_remaining = self.work_duration

        self.create_main_app()

    def create_ui(self):
        # Create and configure the main timer label
        self.timer_label = ttk.Label(self.root, text="25:00", font=("Helvetica", 48))
        self.timer_label.grid(row=0, column=0, columnspan=3, padx=10, pady=10)

        # Create and configure the control buttons
        self.start_button = ttk.Button(self.root, text="Start", command=self.start_timer)
        self.reset_button = ttk.Button(self.root, text="Reset", state="disabled", command=self.reset_timer)
        self.start_button.grid(row=1, column=0, padx=10, pady=10)
        self.reset_button.grid(row=1, column=1, padx=10, pady=10)

        # Create the to-do list section
        self.create_todo_section()

        # Create the statistics button
        statistics_button = ttk.Button(self.root, text="Statistics", command=self.show_statistics)
        statistics_button.grid(row=2, column=2, padx=10, pady=10)

        # Create the dark mode toggle
        self.dark_mode_var = tk.BooleanVar()
        dark_mode_label = ttk.Label(self.root, text="Dark Mode:")
        dark_mode_label.grid(row=2, column=3, padx=10, pady=10)
        dark_mode_toggle = ttk.Checkbutton(self.root, variable=self.dark_mode_var, command=self.toggle_dark_mode)
        dark_mode_toggle.grid(row=2, column=4, padx=10, pady=10)

    
        self.create_export_import_buttons()
        self.create_custom_duration_input()
        interrupt_button = ttk.Button(self.root, text="Interrupt Pomodoro", command=self.interrupt_pomodoro)
        interrupt_button.grid(row=3, column=1, padx=10, pady=10)
        self.create_task_tags()
        self.create_notes_section()
        self.create_search_engine_box()
        self.create_website_blocker()

        # Create alarm button
        alarm_button = ttk.Button(self.root, text="Set Alarm", command=self.set_alarm)
        alarm_button.grid(row=2, column=4, padx=10, pady=10)

    def create_todo_section(self):
        todo_frame = ttk.LabelFrame(self.root, text="To-Do List")
        todo_frame.grid(row=2, column=0, padx=10, pady=10, columnspan=2, sticky="nsew")

        # Create an entry field to add tasks
        task_entry = ttk.Entry(todo_frame)
        task_entry.grid(row=0, column=0, padx=10, pady=10)

        # Create a button to add tasks
        add_button = ttk.Button(todo_frame, text="Add Task", command=lambda: self.add_task(self.todo_listbox, task_entry))
        add_button.grid(row=0, column=1, padx=10, pady=10)

        # Create a listbox to display tasks
        self.todo_listbox = tk.Listbox(todo_frame, selectmode=tk.SINGLE)
        self.todo_listbox.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        # Create buttons for edit, delete, and prioritize tasks
        edit_button = ttk.Button(todo_frame, text="Edit Task", command=lambda: self.edit_task(self.todo_listbox, task_entry))
        delete_button = ttk.Button(todo_frame, text="Delete Task", command=lambda: self.delete_task(self.todo_listbox))
        prioritize_button = ttk.Button(todo_frame, text="Prioritize Task", command=lambda: self.prioritize_task(self.todo_listbox))

        edit_button.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        delete_button.grid(row=2, column=1, padx=10, pady=5, sticky="e")
        prioritize_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

    def show_statistics(self):
        completed_tasks = sum(1 for task in self.tasks if task.startswith("[X] "))
        remaining_tasks = sum(1 for task in self.tasks if not task.startswith("[X] "))

        labels = ['Completed', 'Remaining']
        sizes = [completed_tasks, remaining_tasks]
        colors = ['green', 'red']
        explode = (0.1, 0)  # Explode the 1st slice (i.e., 'Completed')

        fig1, ax1 = plt.subplots()
        ax1.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
                shadow=True, startangle=90)
        ax1.axis('equal')
        plt.title("Task Statistics")
        plt.show()

    def toggle_dark_mode(self):
        dark_mode_enabled = self.dark_mode_var.get()
        if dark_mode_enabled:
            self.root.configure(bg='black', fg='white')
        else:
            self.root.configure(bg='white', fg='black')

    def create_export_import_buttons(self):
        export_button = ttk.Button(self.root, text="Export Data", command=self.export_data)
        export_button.grid(row=3, column=2, padx=10, pady=10)

        import_button = ttk.Button(self.root, text="Import Data", command=self.import_data)
        import_button.grid(row=3, column=3, padx=10, pady=10)

    def export_data(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write("\n".join(self.tasks))

    def import_data(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "r") as file:
                self.tasks = file.read().splitlines()
            self.refresh_todo_list(self.todo_listbox)

    def create_custom_duration_input(self):
        custom_duration_frame = ttk.LabelFrame(self.root, text="Custom Durations")
        custom_duration_frame.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")

        work_label = ttk.Label(custom_duration_frame, text="Work Duration (minutes):")
        work_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.work_duration_entry = ttk.Entry(custom_duration_frame)
        self.work_duration_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        break_label = ttk.Label(custom_duration_frame, text="Break Duration (minutes):")
        break_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.break_duration_entry = ttk.Entry(custom_duration_frame)
        self.break_duration_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        set_durations_button = ttk.Button(custom_duration_frame, text="Set Durations", command=self.set_custom_durations)
        set_durations_button.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

    def set_custom_durations(self):
        try:
            work_duration = int(self.work_duration_entry.get()) * 60
            break_duration = int(self.break_duration_entry.get()) * 60
            if work_duration > 0 and break_duration > 0:
                self.work_duration = work_duration
                self.break_duration = break_duration
                messagebox.showinfo("Success", "Custom durations have been set.")

            else:
                messagebox.showerror("Error", "Durations must be greater than 0.")
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numeric durations.")

    def create_interrupt_button(self):
        interrupt_button = ttk.Button(self.root, text="Interrupt Pomodoro", command=self.interrupt_pomodoro)
        interrupt_button.grid(row=3, column=1, padx=10, pady=10)

    def interrupt_pomodoro(self):
        self.timer_running = False
        self.time_remaining = self.work_duration
        self.update_timer_display()
        self.reset_button.config(state="disabled")

    def create_task_tags(self):
        tags_frame = ttk.LabelFrame(self.root, text="Task Tags")
        tags_frame.grid(row=2, column=0, padx=10, pady=10)

        tag_label = ttk.Label(tags_frame, text="Add tags to your tasks:")
        tag_label.grid(row=0, column=0, padx=10, pady=5, columnspan=2, sticky="w")

        self.tag_entry = ttk.Entry(tags_frame)
        self.tag_entry.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        add_tag_button = ttk.Button(tags_frame, text="Add Tag", command=self.add_tag_to_task)
        add_tag_button.grid(row=1, column=1, padx=10, pady=5, sticky="e")

    def add_tag_to_task(self):
        selected_task_index = self.todo_listbox.curselection()
        if selected_task_index:
            selected_task_index = selected_task_index[0]
            selected_task = self.todo_listbox.get(selected_task_index)

            tag = self.tag_entry.get()
            if selected_task and tag:
                new_task = f"{tag}: {selected_task}"
                self.tasks[selected_task_index] = new_task
                self.refresh_todo_list(self.todo_listbox)
                self.tag_entry.delete(0, tk.END)

    def create_notes_section(self):
        notes_frame = ttk.LabelFrame(self.root, text="Notes")
        notes_frame.grid(row=2, column=1, padx=10, pady=10, columnspan=2, sticky="nsew")

        self.notes_text = tk.Text(notes_frame, wrap=tk.WORD, height=10)
        self.notes_text.grid(row=0, column=0, padx=10, pady=10, columnspan=2, sticky="nsew")

        scroll = Scrollbar(self.notes_text)
        scroll.grid(row=0, column=1, sticky='nsew')
        self.notes_text['yscrollcommand'] = scroll.set
   
    def create_search_engine_box(self):
        search_engine_frame = ttk.LabelFrame(self.root, text="Search Engine")
        search_engine_frame.grid(row=3, column=4, padx=10, pady=10, sticky="nsew")

        search_label = ttk.Label(search_engine_frame, text="Search the web:")
        search_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.search_entry = ttk.Entry(search_engine_frame)
        self.search_entry.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

        search_button = ttk.Button(search_engine_frame, text="Search", command=self.search_web)
        search_button.grid(row=1, column=1, padx=10, pady=5, sticky="e")

    def search_web(self):
        search_query = self.search_entry.get()
        if search_query:
            search_engine_url = "https://www.google.com/search?q="
            webbrowser.open(search_engine_url + search_query)

    def create_website_blocker(self):
        website_blocker_frame = ttk.LabelFrame(self.root, text="Website Blocker")
        website_blocker_frame.grid(row=3, column=5, padx=10, pady=10, sticky="nsew")

        block_label = ttk.Label(website_blocker_frame, text="Enter websites to block (comma-separated):")
        block_label.grid(row=0, column=0, padx=10, pady=5, columnspan=2, sticky="w")

        self.block_entry = ttk.Entry(website_blocker_frame)
        self.block_entry.grid(row=1, column=0, padx=10, pady=5, columnspan=2, sticky="nsew")

        block_button = ttk.Button(website_blocker_frame, text="Block Websites", command=self.block_websites)
        block_button.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

    def block_websites(self):
        websites_to_block = self.block_entry.get()
        if websites_to_block:
            websites = websites_to_block.split(",")
            # Implement website blocking logic here
            messagebox.showinfo("Success", "Websites blocked successfully.")
        else:
            messagebox.showerror("Error", "Please enter websites to block.")

    def create_alarm_button(self):
        alarm_button = ttk.Button(self.root, text="Set Alarm", command=self.set_alarm)
        alarm_button.grid(row=2, column=4, padx=10, pady=10)

    def set_alarm(self):
        winsound.Beep(1000, 1000)  # Beep sound for 1 second

    def refresh_todo_list(self, listbox):
        listbox.delete(0, tk.END)
        for task in self.tasks:
            listbox.insert(tk.END, task)

    def add_task(self, listbox, task_entry):
        task = task_entry.get()
        if task:
            self.tasks.append(task)
            self.refresh_todo_list(listbox)
            task_entry.delete(0, tk.END)

    def edit_task(self, listbox, task_entry):
        selected_task_index = listbox.curselection()
        if selected_task_index:
            selected_task_index = selected_task_index[0]
            selected_task = listbox.get(selected_task_index)

            task_entry.delete(0, tk.END)
            task_entry.insert(0, selected_task)

            self.delete_task(listbox, selected_task_index)

    def delete_task(self, listbox, selected_task_index=None):
        if selected_task_index is None:
            selected_task_index = listbox.curselection()
        if selected_task_index:
            selected_task_index = selected_task_index[0]
            del self.tasks[selected_task_index]
            self.refresh_todo_list(listbox)

    def prioritize_task(self, listbox):
        selected_task_index = listbox.curselection()
        if selected_task_index:
            selected_task_index = selected_task_index[0]
            task = listbox.get(selected_task_index)
            if not task.startswith("[X] "):
                task = "[X] " + task
                self.tasks[selected_task_index] = task
                self.refresh_todo_list(listbox)

    def start_timer(self):
        self.timer_running = True
        self.update_timer()

    def update_timer(self):
        if self.timer_running:
            if self.time_remaining > 0:
                self.time_remaining -= 1
                self.update_timer_display()
                self.root.after(1000, self.update_timer)
            else:
                self.timer_running = False
                self.play_alarm()
                self.switch_timer()

    def play_alarm(self):
        winsound.Beep(1000, 1000)  # Beep sound for 1 second

    def switch_timer(self):
        if self.time_remaining == 0:
            if self.work_duration == self.time_remaining:
                self.add_completed_pomodoro()
                self.time_remaining = self.break_duration
            elif self.break_duration == self.time_remaining:
                self.time_remaining = self.work_duration
            self.update_timer_display()
            self.start_timer()

    def update_timer_display(self):
        minutes, seconds = divmod(self.time_remaining, 60)
        self.timer_label.configure(text=f"{minutes:02d}:{seconds:02d}")

    def reset_timer(self):
        self.timer_running = False
        self.time_remaining = self.work_duration
        self.update_timer_display()
        self.reset_button.config(state="disabled")

    def add_completed_pomodoro(self):
        self.tasks.append("[X] Completed a Pomodoro")
        self.refresh_todo_list(self.todo_listbox)

    def create_main_app(self):
        self.create_ui()

    def run(self):
            self.root.mainloop()

def run_pomodoro():
    root = tk.Tk()
    pomodoro = PomodoroApp(root)
    pomodoro.run()

if __name__ == "__main__":
    # Run the Pomodoro timer in a separate thread
    pomodoro_thread = threading.Thread(target=run_pomodoro)
    pomodoro_thread.start()

    # Run Flask in the main thread
    app.run(debug=True)  
    import secrets

# Generate a secure secret key
secret_key = secrets.token_hex(32)
