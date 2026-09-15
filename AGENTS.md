# AGENTS.md

## Project status

clash-native is an experimental native reimplementation inspired by Mihomo. The project is in a very early stage of development and is not intended for production or general use.

## Project language

Use English for all project content, including source code comments, documentation, commit messages, issue templates, pull request templates, and user-facing command-line output.

## Development guidelines

- Keep changes focused and avoid unrelated modifications.
- Prefer clear, maintainable C++ over clever or unnecessarily complex code.
- Preserve platform boundaries and keep operating-system-specific code isolated in platform adapters.
- Avoid adding dependencies without documenting the reason and evaluating their maintenance and licensing impact.
- Do not treat experimental code as production-ready without explicit validation.

## Validation

- Run the most relevant formatting, build, and test checks for every change.
- Report what was validated and clearly distinguish known limitations or failures from successful checks.
- Do not claim runtime or platform coverage that was not actually tested.
