<p align="center">
  <img src="https://github.com/TheJupiterDev/KoreUI/blob/main/assets/logo.png" alt="KoreUI Logo" height="512" />
</p>

<h1 align="center">KoreUI</h1>

<p align="center">
  <strong>Dynamic GUI Generator from JSON Schema</strong><br />
  Build fully-functional PySide6 interfaces from JSON Schema — including complex features like <code>if/then/else</code>, <code>allOf</code>, dynamic arrays, and real-time validation.
</p>

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

```pip install koreui```

Requirements:

- Python 3.10+
- PySide6

---

## 📦 Installation

```bash
pip install koreui
```

Requirements:
- Python 3.10+
- PySide6

## 🧑‍💻 Usage

1. Create a JSON schema file (e.g., `schema.json`):
```json
{
    "title": "User Profile",
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "title": "Full Name"
        }
    }
}
```

2. Use KoreUI in your Python code:
```python
from PySide6.QtWidgets import QApplication
from koreui import JsonSchemaForm, load_schema

# Create Qt application
app = QApplication([])

# Load schema and create form
schema = load_schema('schema.json')
form = JsonSchemaForm(schema)

# Show form and run application
form.show()
app.exec()
```

3. Get form data:
```python
# After form is filled out
data = form.get_form_data()
print(data)  # Dictionary with form values
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
