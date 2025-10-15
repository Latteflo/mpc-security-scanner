# Contributing to MCP Security Scanner

Thank you for your interest in contributing! 🎉

## How to Contribute

### Reporting Bugs
- Use GitHub Issues
- Include reproduction steps
- Provide error messages and logs

### Suggesting Features
- Open an issue with the `enhancement` label
- Describe the use case
- Explain why it's valuable

### Pull Requests

1. **Fork the repository**
2. **Create a branch**
```bash
   git checkout -b feature/my-feature
```

3. **Make your changes**
   - Write tests for new features
   - Update documentation
   - Follow code style (Black)

4. **Run tests**
```bash
   pytest
   black src/ tests/
   ruff check src/ tests/
```

5. **Commit with conventional commits**
```bash
   git commit -m "feat: add new security check"
   git commit -m "fix: resolve authentication bypass"
   git commit -m "docs: update README"
```

6. **Push and create PR**
```bash
   git push origin feature/my-feature
```

## Development Setup
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/mcp-security-scanner.git
cd mcp-security-scanner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest
```

## Code Style

- Use **Black** for formatting
- Use **Ruff** for linting
- Write **type hints**
- Add **docstrings** to functions
- Keep functions **small and focused**

## Testing

- Write tests for all new features
- Maintain > 80% code coverage
- Use pytest fixtures
- Test edge cases

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `test:` - Tests
- `refactor:` - Code refactoring
- `chore:` - Maintenance

## Questions?

Open an issue or reach out to the maintainers!
