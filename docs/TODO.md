## To-Do List

- Identify the current main() flow and extract the reusable analysis steps.
- Move the per-IP work into a function that accepts one IP and returns the run result.
- Add input validation for both IPv4 and IPv6.
- Reject empty or invalid IP input before any API calls start.
- Split the code into separate parts for validation, fetching, reporting, and GUI wiring.
- Keep the existing providers and add Pulsedive, Shodan InternetDB, Criminal IP, and IPQualityScore.
- Add a fetch function for each new provider.
- Map each new provider’s result into the report output.
- Design a small Tkinter window with input, buttons, progress, and results.
- Add a run action that starts the full analysis.
- Run the analysis on a background worker so the UI stays responsive.
- Send progress and completion updates back to the window.
- Add buttons to open the CSV, HTML map, and chart files.
- Keep .env loading working in the GUI version.
- Preserve the current report folder name and file layout.
- Add readable logs and consistent error messages.
- Start the GUI directly without terminal prompts.
- Update the README with the GUI launch steps and secret setup.

## Guiding decisions

- Use Tkinter to stay lightweight.
- Keep the existing API and report-generation logic as much as possible.
- Open the folium map in the browser instead of embedding it.
- Aim for enterprise-like polish through structure and clarity, not extra dependencies.