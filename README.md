

# 📚 Library Management System

A complete **Library Management System** built to manage books, users, and library operations efficiently. This project was created as part of a **Summer 2025 academic initiative** to apply real-world software development concepts, integrating **database operations**, **user interaction**, and **email automation**.

🎥 **[Watch the Demo Video](https://www.youtube.com/watch?v=EUgHJfPR3WE)**

[![Watch on YouTube](iitgn_logo.png)](https://www.youtube.com/watch?v=EUgHJfPR3WE)

> *This video demonstrates all the features including book handling, user registration, issuing/returning books, and the automated email notifications.*


---

## 🚀 Features

* 📖 **Book Management**

  * Add, update, delete, and search for books.
  * Store metadata: title, author, ISBN, quantity, category.

* 👤 **User Management**

  * Register library members.
  * View and manage individual borrowing history.

* 📦 **Book Issue & Return**

  * Issue books to users with date tracking.
  * Return books with optional fine calculation.
  * Track overdue books.

* 📧 **Email Notification System**

  * Sends automated email notifications to users:

    * 📬 On book issue/return.
    * ⏰ Reminder before the due date.
    * ⚠️ Alert if a book is overdue.
  * Uses **SMTP with Gmail/Yahoo/Custom server** (mention your setup).
  * Ensures members stay informed and avoid penalties.

* 📊 **Dashboard**

  * Displays stats: total books, issued books, available inventory, registered members.

* 🔐 **Admin Authentication (if implemented)**

---

## 🛠️ Tech Stack

| Layer           | Technology                                       |
| --------------- | ------------------------------------------------ |
| Frontend        | Python (Tkinter / Flask / React – specify yours) |
| Backend         | Python (Core logic, Email using `smtplib`)       |
| Database        | SQLite / MySQL                                   |
| Email Service   | SMTP (Gmail/Yahoo API or custom SMTP server)     |
| IDE             | VS Code / PyCharm                                |
| Version Control | Git & GitHub                                     |

---




> *This video demonstrates all the features including book handling, user registration, issuing/returning books, and the automated email notifications.*

---



## 🏁 How to Run

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/library-management-system.git
   cd library-management-system
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Configure email credentials:

   * Open `email_config.py` or `.env` (if exists).
   * Add your SMTP email ID, password (or app password), and server settings.

4. Run the application:

   ```bash
   python main.py
   ```

---


---



