# KubeChat Development Guide for Claude Code

## Project Overview
KubeChat is a Kubernetes operator that enables natural language management of Kubernetes clusters. This project follows the BMAD-METHOD for systematic AI-driven development.

## Current Development Phase
**Phase**: Foundation Setup
**Goal**: Create basic Kubernetes operator with minimal NLP integration
**Timeline**: 4 weeks

## Active Story Location
`.bmad/stories/current-story.md` - Always check this file first for current development context

## Claude Code Instructions

### Always Follow This Sequence:
1. Read `.bmad/stories/current-story.md` for current task
2. Check `.bmad/planning/current-epic.md` for broader context
3. Reference `docs/architecture.md` for technical decisions
4. Follow `docs/development/coding-standards.md` for implementation
5. Update story progress after each completed task

### Code Implementation Rules:
- **Never skip error handling** - Every function must handle errors appropriately
- **Always add tests** - Minimum 80% code coverage required
- **Follow Go conventions** - Use effective Go patterns and idioms
- **Kubernetes best practices** - Respect RBAC, use proper client libraries
- **Structured logging** - Use logr for consistent logging
- **Documentation** - Add godoc comments for all public functions

### Current Technology Stack:
- **Language**: Go 1.22+
- **Framework**: Operator SDK + controller-runtime
- **Database**: Start with in-memory, migrate to PostgreSQL later
- **NLP**: OpenAI API integration (simple text completion initially)
- **Frontend**: Defer to Phase 2

### Development Workflow:
1. Read current story and understand requirements
2. Implement code following acceptance criteria
3. Write comprehensive tests
4. Update documentation
5. Mark story tasks as complete
6. Move to next story when current is 100% done

### File Structure Priority for Context:
1. `.bmad/stories/current-story.md` (highest priority)
2. `docs/architecture.md`
3. `docs/development/coding-standards.md`
4. `api/v1/` (CRD definitions)
5. `pkg/controllers/` (main logic)

## Important Notes:
- This is a learning project - prioritize clear, well-documented code
- Build incrementally - each story must be complete before moving forward
- Focus on functionality over premature optimization
- Safety first - all operations must be validated before execution
