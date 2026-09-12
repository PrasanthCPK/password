# Strong Password Generator

A small static web app that generates a cryptographically secure 14-character
password in the browser. Plain HTML, CSS, and vanilla JavaScript: no backend,
build step, dependencies, or API keys.

## Password rules

- Exactly 14 characters
- At least one uppercase letter, lowercase letter, number, and special character
- No ambiguous characters: `O`, `0`, `I`, `l`, `1`, `|`, backtick
- No spaces
- No repeated runs (`aaa`, `111`) or sequential runs (`abc`, `cba`, `123`, `321`)
- A fresh random password every time, generated with `crypto.getRandomValues()`

## Files

| File         | Purpose                                              |
| ------------ | ---------------------------------------------------- |
| `index.html` | Page structure, labels, and accessibility attributes |
| `styles.css` | Card layout, light/dark themes, responsive rules     |
| `script.js`  | Secure generation, validation, copy, and UI wiring   |

## Run locally

Open `index.html` in any modern browser. No server is required.

## Deploy to GitHub Pages

1. Push these three files to the root of a GitHub repository.
2. In the repository, open **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to *Deploy from a branch*,
   choose your branch (for example `main`) and the `/ (root)` folder, then save.
4. After a minute the site is live at `https://<user>.github.io/<repo>/`.
