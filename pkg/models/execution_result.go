package models

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// OutputFormatter provides methods for formatting command output
type OutputFormatter struct{}

// NewOutputFormatter creates a new output formatter
func NewOutputFormatter() *OutputFormatter {
	return &OutputFormatter{}
}

// FormatOutput formats command output with syntax highlighting and human-readable structure
func (of *OutputFormatter) FormatOutput(result *CommandExecutionResult, command string) {
	if result == nil {
		return
	}

	// Apply syntax highlighting and formatting based on command type and output
	result.FormattedOutput = of.formatWithSyntaxHighlighting(result.Output, command, result.Success)
}

// formatWithSyntaxHighlighting applies syntax highlighting and formatting to output
func (of *OutputFormatter) formatWithSyntaxHighlighting(output, command string, success bool) string {
	if output == "" {
		if success {
			return "✅ Command executed successfully (no output)"
		}
		return "❌ Command failed (no output)"
	}

	// Determine command type for appropriate formatting
	commandType := of.determineCommandType(command)
	
	var formatted string
	switch commandType {
	case "get":
		formatted = of.formatGetOutput(output)
	case "describe":
		formatted = of.formatDescribeOutput(output)
	case "logs":
		formatted = of.formatLogsOutput(output)
	case "version":
		formatted = of.formatVersionOutput(output)
	case "create", "apply":
		formatted = of.formatCreateOutput(output)
	case "delete":
		formatted = of.formatDeleteOutput(output)
	default:
		formatted = of.formatGenericOutput(output)
	}

	// Add command context header
	header := fmt.Sprintf("🔧 Command: %s\n", command)
	if success {
		header = fmt.Sprintf("✅ Command: %s\n", command)
	} else {
		header = fmt.Sprintf("❌ Command: %s\n", command)
	}

	return header + "\n" + formatted
}

// determineCommandType extracts the kubectl command type
func (of *OutputFormatter) determineCommandType(command string) string {
	// Remove kubectl prefix if present
	command = strings.TrimSpace(command)
	if strings.HasPrefix(command, "kubectl ") {
		command = strings.TrimPrefix(command, "kubectl ")
	}

	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "unknown"
	}

	return strings.ToLower(parts[0])
}

// formatGetOutput formats kubectl get command output with table highlighting
func (of *OutputFormatter) formatGetOutput(output string) string {
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return output
	}

	var formatted strings.Builder
	
	for i, line := range lines {
		if i == 0 {
			// Header row - make it bold/highlighted
			formatted.WriteString("📋 " + of.highlightTableHeader(line) + "\n")
		} else if strings.TrimSpace(line) != "" {
			// Data rows - format based on status
			formatted.WriteString(of.formatTableRow(line) + "\n")
		}
	}

	return strings.TrimSpace(formatted.String())
}

// formatDescribeOutput formats kubectl describe command output
func (of *OutputFormatter) formatDescribeOutput(output string) string {
	lines := strings.Split(output, "\n")
	var formatted strings.Builder

	for _, line := range lines {
		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, " ") {
			// Section headers
			formatted.WriteString("📌 " + line + "\n")
		} else if strings.Contains(line, ":") && strings.HasPrefix(line, "  ") {
			// Key-value pairs
			formatted.WriteString(of.highlightKeyValue(line) + "\n")
		} else {
			formatted.WriteString(line + "\n")
		}
	}

	return strings.TrimSpace(formatted.String())
}

// formatLogsOutput formats kubectl logs output
func (of *OutputFormatter) formatLogsOutput(output string) string {
	lines := strings.Split(output, "\n")
	var formatted strings.Builder
	
	formatted.WriteString("📝 Container Logs:\n\n")
	
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			// Add timestamp highlighting if present
			if of.containsTimestamp(line) {
				formatted.WriteString(of.highlightTimestamp(line) + "\n")
			} else {
				formatted.WriteString("   " + line + "\n")
			}
		}
	}

	return strings.TrimSpace(formatted.String())
}

// formatVersionOutput formats kubectl version output
func (of *OutputFormatter) formatVersionOutput(output string) string {
	lines := strings.Split(output, "\n")
	var formatted strings.Builder
	
	formatted.WriteString("🔧 Version Information:\n\n")
	
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			if strings.Contains(line, "Client Version") {
				formatted.WriteString("💻 " + line + "\n")
			} else if strings.Contains(line, "Server Version") {
				formatted.WriteString("🖥️  " + line + "\n")
			} else {
				formatted.WriteString("   " + line + "\n")
			}
		}
	}

	return strings.TrimSpace(formatted.String())
}

// formatCreateOutput formats kubectl create/apply output
func (of *OutputFormatter) formatCreateOutput(output string) string {
	lines := strings.Split(output, "\n")
	var formatted strings.Builder
	
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			if strings.Contains(line, "created") {
				formatted.WriteString("✨ " + line + "\n")
			} else if strings.Contains(line, "configured") {
				formatted.WriteString("🔄 " + line + "\n")
			} else if strings.Contains(line, "unchanged") {
				formatted.WriteString("⏸️  " + line + "\n")
			} else {
				formatted.WriteString("   " + line + "\n")
			}
		}
	}

	return strings.TrimSpace(formatted.String())
}

// formatDeleteOutput formats kubectl delete output
func (of *OutputFormatter) formatDeleteOutput(output string) string {
	lines := strings.Split(output, "\n")
	var formatted strings.Builder
	
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			if strings.Contains(line, "deleted") {
				formatted.WriteString("🗑️  " + line + "\n")
			} else {
				formatted.WriteString("   " + line + "\n")
			}
		}
	}

	return strings.TrimSpace(formatted.String())
}

// formatGenericOutput provides basic formatting for unknown command types
func (of *OutputFormatter) formatGenericOutput(output string) string {
	// Try to detect if it's JSON and format it
	if of.isJSON(output) {
		return of.formatJSON(output)
	}
	
	// Try to detect if it's YAML and format it
	if of.isYAML(output) {
		return of.formatYAML(output)
	}
	
	// Default formatting with line prefixes
	lines := strings.Split(output, "\n")
	var formatted strings.Builder
	
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			formatted.WriteString("   " + line + "\n")
		}
	}

	return strings.TrimSpace(formatted.String())
}

// highlightTableHeader adds visual emphasis to table headers
func (of *OutputFormatter) highlightTableHeader(header string) string {
	return strings.ToUpper(header)
}

// formatTableRow formats individual table rows with status indicators
func (of *OutputFormatter) formatTableRow(row string) string {
	// Look for common status indicators
	if strings.Contains(row, "Running") {
		return "🟢 " + row
	} else if strings.Contains(row, "Pending") {
		return "🟡 " + row
	} else if strings.Contains(row, "Failed") || strings.Contains(row, "Error") {
		return "🔴 " + row
	} else if strings.Contains(row, "Terminating") {
		return "🟠 " + row
	} else if strings.Contains(row, "Completed") || strings.Contains(row, "Succeeded") {
		return "✅ " + row
	}
	
	return "   " + row
}

// highlightKeyValue adds visual formatting to key-value pairs
func (of *OutputFormatter) highlightKeyValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 2 {
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		return fmt.Sprintf("  🔸 %s: %s", key, value)
	}
	return line
}

// containsTimestamp checks if a line contains a timestamp pattern
func (of *OutputFormatter) containsTimestamp(line string) bool {
	// Common timestamp patterns in logs
	timestampPatterns := []string{
		`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`,           // ISO 8601
		`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`,           // Standard format
		`\w{3} \d{2} \d{2}:\d{2}:\d{2}`,                 // Syslog format
	}
	
	for _, pattern := range timestampPatterns {
		matched, _ := regexp.MatchString(pattern, line)
		if matched {
			return true
		}
	}
	return false
}

// highlightTimestamp adds visual emphasis to lines with timestamps
func (of *OutputFormatter) highlightTimestamp(line string) string {
	return "⏰ " + line
}

// isJSON checks if the output appears to be JSON
func (of *OutputFormatter) isJSON(output string) bool {
	trimmed := strings.TrimSpace(output)
	return strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")
}

// formatJSON formats JSON output with proper indentation
func (of *OutputFormatter) formatJSON(output string) string {
	var jsonData interface{}
	err := json.Unmarshal([]byte(output), &jsonData)
	if err != nil {
		return output // Return original if not valid JSON
	}
	
	formatted, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return output
	}
	
	return "📄 JSON Output:\n\n" + string(formatted)
}

// isYAML checks if the output appears to be YAML
func (of *OutputFormatter) isYAML(output string) bool {
	// First check if it's JSON - if so, it's not YAML
	if of.isJSON(output) {
		return false
	}
	
	// Simple heuristic: contains lines starting with keys followed by colons
	lines := strings.Split(output, "\n")
	yamlLines := 0
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Look for YAML-like patterns: key: value (not JSON-like)
		if strings.Contains(trimmed, ":") && !strings.HasPrefix(trimmed, "#") &&
			!strings.HasPrefix(trimmed, "{") && !strings.HasSuffix(trimmed, "}") {
			yamlLines++
		}
	}
	
	// Consider it YAML if more than 30% of non-empty lines have key: pattern
	nonEmptyLines := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			nonEmptyLines++
		}
	}
	
	if nonEmptyLines > 0 {
		return float64(yamlLines)/float64(nonEmptyLines) > 0.3
	}
	
	return false
}

// formatYAML adds visual formatting to YAML output
func (of *OutputFormatter) formatYAML(output string) string {
	lines := strings.Split(output, "\n")
	var formatted strings.Builder
	
	formatted.WriteString("📋 YAML Output:\n\n")
	
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			formatted.WriteString("\n")
			continue
		}
		
		if strings.HasPrefix(line, "apiVersion:") || strings.HasPrefix(line, "kind:") {
			formatted.WriteString("🏷️  " + line + "\n")
		} else if strings.HasPrefix(line, "metadata:") {
			formatted.WriteString("📝 " + line + "\n")
		} else if strings.HasPrefix(line, "spec:") {
			formatted.WriteString("⚙️  " + line + "\n")
		} else if strings.HasPrefix(line, "status:") {
			formatted.WriteString("📊 " + line + "\n")
		} else {
			formatted.WriteString("   " + line + "\n")
		}
	}
	
	return strings.TrimSpace(formatted.String())
}