<p align="center">
  <img src="https://github.com/TheJupiterDev/KoreUI/blob/main/assets/logo.png" alt="KoreUI Logo" height="512" />
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

###### *Soon. Denser schemas may or may not fail- this is being looked into.

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
  "title": "User Profile",
  "type": "object",
  "required": ["name", "age", "email"],
  "properties": {
    "name": {
      "type": "string",
      "title": "Full Name"
    },
    "age": {
      "type": "integer",
      "title": "Age",
      "minimum": 0
    },
    "email": {
      "type": "string",
      "format": "email",
      "title": "Email Address"
    },
    "subscribe": {
      "type": "boolean",
      "title": "Subscribe to Newsletter"
    },
    "bio": {
      "type": "string",
      "title": "Short Bio",
      "maxLength": 250
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

GNU Affero General Public License v3.0
