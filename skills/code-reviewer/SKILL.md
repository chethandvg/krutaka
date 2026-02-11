---
name: code-reviewer
description: Reviews code changes for bugs, style issues, and best practices
allowed-tools: read_file,search_files,list_files
model: claude-sonnet-4-5-20250929
version: 1.0.0
---

# Code Review Skill

## Instructions

When reviewing code, follow this systematic approach:

1. **Read the files** specified by the user
2. **Analyze** for the following aspects:
   - Correctness: Does the code work as intended?
   - Performance: Are there any performance bottlenecks?
   - Security: Are there any security vulnerabilities?
   - Readability: Is the code clear and maintainable?
   - Best practices: Does it follow language-specific conventions?

3. **Provide specific line-by-line feedback** when issues are found
4. **Suggest concrete improvements** with code examples
5. **Highlight what's done well** to reinforce good practices

## Output Format

Use markdown with the following structure:

### File: `path/to/file.ext`

#### ✅ What's Good
- Highlight positive aspects

#### ⚠️ Issues Found
- List issues with line references
- Provide severity (Critical/High/Medium/Low)

#### 💡 Suggestions
```language
// Show improved code examples
```

## Allowed Tools

This skill can use the following tools:
- `read_file`: To read the code files
- `search_files`: To search for patterns across the codebase
- `list_files`: To discover related files

## Model Preference

This skill works best with `claude-sonnet-4-5-20250929` for detailed code analysis.
