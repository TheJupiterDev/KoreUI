<p align="center">
  <img src="https://github.com/TheJupiterDev/KoreUI/blob/main/assets/logo.png" alt="KoreUI Logo" height="1024" />
</p>

<h1 align="center">KoreUI</h1>

<p align="center">
  <strong>Dynamic GUI Generator from JSON Schema</strong><br />
  Build fully-functional PySide6 interfaces from JSON Schema — including complex features like <code>if/then/else</code>, <code>allOf</code>, dynamic arrays, and real-time validation.
</p>

---

> ⚠️ This project is still in pre alpha stages!

---

## 🚀 Features

- 📄 Full support for JSON Schema Draft 2020-12*
- 🧩 Handles `if` / `then` / `else`, `allOf`, `anyOf`, `oneOf`, `$ref`, and more  
- 🧠 Live conditionals — forms change in real-time based on inputs  
- 🛠️ Built-in validation with contextual error messages  
- 🧪 Ideal for form builders, config tools, admin panels, or low-code platforms  

-# *Soon. When the Beta releases, it will comply.

---

## 📦 Installation

Run the following:

```pip install pyside6```

Requirements:

- Python 3.10+
- PySide6

---

## 🧑‍💻 Usage

To start the application:

```python app.py```

Edit the `example_schema.json` file to customize your form structure.

---

## 🧪 Example Schema
```json
{
    "type": "object",
    "properties": {
    "mode": {
        "type": "string",
        "enum": ["simple", "advanced"]
    },
    "settings": {
        "if": {
        "properties": { "mode": { "const": "advanced" } }
        },
        "then": {
        "properties": { "threshold": { "type": "number" } }
        },
        "else": {
        "properties": { "notes": { "type": "string" } }
        },
        "type": "object"
    }
    }
}
```

---

## 🧱 Architecture

- `src/koreui.py` – Core schema resolver, validator, and widget logic
- `src/loader.py` – A helper script to load a Schema from a JSON
- `app.py` – App entry point  
- `example_schema.json` – Example JSON Schema used to render a dynamic form  

---

## 📝 License

MIT License — free for personal and commercial use.

---

## 🙌 Credits

Built using PySide6, JSON Schema, and caffeine.
And maybe a little AI.
