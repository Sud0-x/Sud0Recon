# Contributing to Sud0Recon

Thank you for your interest in contributing to Sud0Recon! We welcome contributions from the community.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your feature or bug fix
4. Make your changes
5. Test your changes thoroughly
6. Submit a pull request

## Development Setup

```bash
# Clone the repository
git clone https://github.com/Sud0-x/Sud0Recon.git
cd Sud0Recon

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .[dev]  # Install development dependencies
```

## Code Style

- Follow PEP 8 style guidelines
- Use Black for code formatting: `black src/`
- Use type hints where appropriate
- Write clear, descriptive docstrings
- Keep functions focused and modular

## Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=sud0recon tests/
```

## Plugin Development

Sud0Recon uses a plugin-based architecture. To create a new plugin:

1. Create a new Python file in `src/sud0recon/plugins/`
2. Inherit from the base plugin class
3. Implement required methods
4. Add appropriate error handling
5. Include comprehensive documentation

## Submitting Changes

1. Ensure all tests pass
2. Update documentation if needed
3. Add a brief description of changes to CHANGELOG.md
4. Create a pull request with a clear description

## Code Review Process

- All submissions require review
- Maintainers will provide feedback
- Changes may be requested before merging
- Be responsive to feedback and questions

## Bug Reports

When reporting bugs, please include:
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages (if any)

## Feature Requests

For new features:
- Describe the use case
- Explain the expected behavior
- Consider backward compatibility
- Be open to discussion and alternatives

## Contact

For questions about contributing: sud0x.dev@proton.me

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
