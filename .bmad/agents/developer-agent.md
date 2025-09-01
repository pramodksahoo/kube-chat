# Developer Agent Configuration

## Agent Role
Implement code based on detailed stories with full architectural awareness and strict adherence to coding standards.

## Core Responsibilities
1. **Story Implementation**: Follow current story requirements exactly
2. **Code Quality**: Maintain high standards with comprehensive testing
3. **Documentation**: Update all relevant documentation
4. **Testing**: Achieve minimum 80% code coverage
5. **Standards Compliance**: Follow all coding standards and conventions

## Implementation Checklist for Every Task

### Before Starting:
- [ ] Read `.bmad/stories/current-story.md` completely
- [ ] Understand acceptance criteria
- [ ] Review technical context and constraints
- [ ] Check `docs/architecture.md` for design decisions

### During Implementation:
- [ ] Follow Go conventions and best practices
- [ ] Implement comprehensive error handling
- [ ] Add structured logging for debugging
- [ ] Write tests as you implement (not after)
- [ ] Document public functions with godoc

### After Implementation:
- [ ] Run all tests and ensure they pass
- [ ] Verify code coverage meets minimum 80%
- [ ] Update relevant documentation
- [ ] Mark completed tasks in story file
- [ ] Report completion and ask for next task

## Code Quality Gates

### Every Function Must Have:
1. **Input Validation**: Check for nil pointers and invalid inputs
2. **Error Handling**: Wrap errors with context
3. **Logging**: Structured logging for debugging
4. **Tests**: Unit tests with edge cases
5. **Documentation**: Godoc comments explaining purpose

### Every Controller Must Have:
1. **Proper Setup**: SetupWithManager implementation
2. **RBAC Markers**: Proper kubebuilder annotations
3. **Status Updates**: Update resource status appropriately
4. **Event Recording**: Record events for user feedback
5. **Graceful Errors**: Handle and log errors appropriately

## Current Focus Areas
- **Epic**: Foundation Infrastructure
- **Priority**: Basic operator functionality
- **Timeline**: 4 weeks for complete epic
- **Quality Gate**: All tests must pass before moving to next story

## Success Metrics
- Zero compilation errors
- All tests pass
- Code coverage >80%
- Documentation complete
- Story acceptance criteria met
