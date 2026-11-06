# CRMS interface update

- Dark and light mode now have separate CSS variables. The selected mode persists in localStorage.
- Workspace navigation has subtle hover movement, an active indicator, and icon motion.
- Change Password, account profile, and Logout are in the bottom of the left sidebar, replacing the version footer.
- Flask routes, forms, and database files are unchanged.

To test: run `python app.py`, log in, switch themes, refresh, then hover workspace links and use Change Password / Logout. Use Ctrl+F5 if the browser has cached the previous stylesheet.
