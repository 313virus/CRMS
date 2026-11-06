# CRMS visual refresh

This version updates the user interface only. Flask routes, SQL schema, risk scoring, forms and permissions remain unchanged.

- `templates/base.html`: sidebar and utility top bar for authenticated pages.
- `static/modern.css`: design tokens, layouts, responsive styles and login page refresh.
- `static/app.js`: mobile navigation toggle.

Colors: slate `#162a30`, teal `#087f78`, canvas `#f5f7f9`.

To change colors, edit the variables at the top of `static/modern.css`.

Start: `pip install -r requirements.txt` then `python app.py`.
