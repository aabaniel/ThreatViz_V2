## To-Do List

- Extract the main() flow into a callable analysis controller for a single IP.
- Split the script into clear layers for validation, data fetch, report generation, and GUI presentation.
- Build a Tkinter window with a professional header, IP input, Run/Clear/Exit controls, a progress log, and a results panel.
- Run analysis work on a background thread so the UI stays responsive.
- Add actions to open the generated CSV, HTML map, and PNG chart outputs.
- Keep configuration loading from .env and preserve the current report folder structure.
- Add structured logging, consistent errors, and a GUI startup path that does not require terminal interaction.
- Update the README with GUI usage and secret setup instructions.

## Guiding decisions

- Use Tkinter to stay lightweight.
- Keep the existing API and report-generation logic as much as possible.
- Open the folium map in the browser instead of embedding it.
- Aim for enterprise-like polish through structure and clarity, not extra dependencies.