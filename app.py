import sys
from PySide6.QtWidgets import QApplication, QScrollArea, QVBoxLayout, QWidget

from src.koreui import JsonSchemaForm
from src.loader import load_schema


def main():
    try:
        # Load the schema
        schema = load_schema('example_schema.json')
        
        # Create the application
        app = QApplication(sys.argv)
        
        # Create main window widget
        main_widget = QWidget()
        main_widget.setWindowTitle("JSON Schema Form")
        main_widget.resize(800, 600)
        
        # Create layout
        layout = QVBoxLayout(main_widget)
        
        # Create the form
        form = JsonSchemaForm(schema)
        
        # Create scroll area and add form to it
        scroll_area = QScrollArea()
        scroll_area.setWidget(form)
        scroll_area.setWidgetResizable(True)
        
        # Add scroll area to layout
        layout.addWidget(scroll_area)
        
        # Show the main widget
        main_widget.show()
        
        # Run the application
        sys.exit(app.exec())
        
    except FileNotFoundError:
        print("Error: example_schema.json file not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()