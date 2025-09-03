# Current Epic: Epic 1 - Core Natural Language Processing Foundation

## Epic Status
**Status:** Ready to Start  
**Priority:** P0 (Critical - Foundation Epic)  
**Estimated Duration:** 6-8 weeks  
**Dependencies:** None (foundational epic)

## Epic Overview
Establish the fundamental natural language to kubectl command translation capability with basic safety controls and user confirmation workflows.

## Key Deliverables
- Natural language processing service architecture
- kubectl command translation engine with 90%+ accuracy
- Safety assessment and risk categorization (SAFE/CAUTION/DESTRUCTIVE)
- Command preview and confirmation workflows
- Basic error handling and user feedback
- Integration with Kubernetes operator framework

## Stories in This Epic
1. **Story 1.1:** Natural Language Query Translation (8 points)
2. **Story 1.2:** Write Operation Safety Controls (5 points) 
3. **Story 1.3:** Command Execution and Results Display (5 points)
4. **Story 1.4:** Conversational Context Support (8 points)
5. **Story 1.5:** Basic Error Handling and Recovery (3 points)

**Total Story Points:** 29 points

## Technology Stack
- **Backend:** Go-based microservice with gRPC and REST APIs
- **NLP Engine:** OpenAI API integration with local Ollama fallback option
- **Kubernetes Integration:** controller-runtime framework with custom resources
- **Data Storage:** In-memory caching for session state

## Success Criteria
- [ ] Natural language queries translate to correct kubectl commands with 90%+ accuracy
- [ ] All write operations require explicit user confirmation
- [ ] Command execution provides clear feedback and results formatting
- [ ] Conversational context is maintained within sessions
- [ ] Error handling provides actionable feedback to users

## Next Steps
1. Start with Epic 1 development
2. Existing code in the repository can be referenced/reused where applicable
3. Developers will evaluate existing Go operator code for foundation
4. Epic 2 (Authentication) can begin parallel development after Story 1.1 completion

## Dependencies for Future Epics
- **Epic 2:** Will integrate with session management for user authentication
- **Epic 3:** Will capture all command translation and execution events for audit
- **Epic 4:** Will consume NLP service APIs for web interface
- **Epic 5-8:** Will build upon this foundation for advanced features

## Development Notes
The existing codebase contains:
- Go operator framework setup (`/cmd/operator/`, `/pkg/`, `/api/v1/`)
- React frontend foundation (`/web/`)
- Basic testing infrastructure

Developers should evaluate existing code for reusability while ensuring it aligns with Epic 1 requirements and architecture specifications.