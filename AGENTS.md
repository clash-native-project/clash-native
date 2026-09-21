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
- After every implementation change, append a concise entry dated `YYYY-MM-DD` to `docs/implementation-log.md` describing what was done. Keep this implementation log separate from `docs/architecture.md`.
- Before every commit, run `clang-format` on the repository's C++ sources and
  headers and run `gofmt` on the repository's Go sources. Do not format generated
  build trees, vendored dependencies, or other third-party sources.

## Platform documentation

- Before platform-specific implementation or validation, read the matching document under `docs/platform/`.
- Use `docs/platform/windows.md` for Windows work and the corresponding `<platform>.md` document for other platforms.
- Keep platform-specific toolchain choices, commands, validated scope, and known limitations in the matching platform document. Do not infer one platform's setup or validation from another platform.

## Validation

- Run the most relevant formatting, build, and test checks for every change.
- Report what was validated and clearly distinguish known limitations or failures from successful checks.
- Do not claim runtime or platform coverage that was not actually tested.
